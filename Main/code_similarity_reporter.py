#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from __future__ import annotations

import argparse
import difflib
import html
import os
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple


ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED = "\033[91m"
ANSI_BLUE = "\033[94m"
ANSI_BOLD = "\033[1m"
ANSI_RESET = "\033[0m"


@dataclass
class FunctionBlock:
    name: str
    start: int
    end: int
    text: str
    normalized_text: str
    line_count: int


@dataclass
class MatchBlock:
    a_start: int
    b_start: int
    size: int
    kind: str


def read_text_file(path: Path) -> str:
    """Lit un fichier source avec plusieurs encodages possibles."""
    raw = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def split_lines_keep(text: str) -> List[str]:
    return text.splitlines()


def strip_c_comments(text: str) -> str:
    """Supprime commentaires C/C++ sans être parfait, mais suffisant pour score normalisé."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*", "", text)
    return text


def normalize_line(line: str) -> str:
    line = strip_c_comments(line)
    line = line.strip()
    line = re.sub(r"\s+", " ", line)
    return line


def normalize_code(text: str) -> str:
    text = strip_c_comments(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def non_empty(lines: Sequence[str]) -> List[str]:
    return [x for x in lines if x.strip()]


def count_nonempty(lines: Sequence[str]) -> int:
    return sum(1 for x in lines if x.strip())


def pct(part: float, total: float) -> float:
    if total == 0:
        return 0.0
    return 100.0 * part / total


def multiset_intersection_count(a: Sequence[str], b: Sequence[str]) -> int:
    ca = Counter(a)
    cb = Counter(b)
    return sum((ca & cb).values())


def lcs_order_count(a: Sequence[str], b: Sequence[str]) -> int:
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return sum(block.size for block in matcher.get_matching_blocks())


def find_exact_blocks(a_lines: Sequence[str], b_lines: Sequence[str], min_block: int = 3) -> List[MatchBlock]:
    matcher = difflib.SequenceMatcher(None, a_lines, b_lines, autojunk=False)
    blocks = []
    for block in matcher.get_matching_blocks():
        if block.size >= min_block:
            blocks.append(MatchBlock(block.a + 1, block.b + 1, block.size, "exact"))
    return blocks


def find_normalized_blocks(a_lines: Sequence[str], b_lines: Sequence[str], min_block: int = 3) -> List[MatchBlock]:
    a_norm = [normalize_line(x) for x in a_lines]
    b_norm = [normalize_line(x) for x in b_lines]

    # On garde les indices mais on compare les lignes normalisées.
    matcher = difflib.SequenceMatcher(None, a_norm, b_norm, autojunk=False)
    blocks = []
    for block in matcher.get_matching_blocks():
        if block.size >= min_block:
            # Ignore les blocs qui ne sont que vides/commentaires après normalisation.
            segment = a_norm[block.a:block.a + block.size]
            if any(x.strip() for x in segment):
                blocks.append(MatchBlock(block.a + 1, block.b + 1, block.size, "normalized"))
    return blocks


def brace_delta(line: str) -> int:
    """Compte approximativement les accolades hors chaînes."""
    # Simplification volontaire: suffisant pour un rapport local.
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line.count("{") - line.count("}")


def extract_c_functions(lines: Sequence[str]) -> Dict[str, FunctionBlock]:
    """
    Extraction heuristique de fonctions C/C++.
    Ne compile pas le code: détecte les signatures suivies d'une accolade.
    """
    functions: Dict[str, FunctionBlock] = {}

    control_keywords = {
        "if", "for", "while", "switch", "catch", "sizeof", "return",
        "do", "else", "case"
    }

    signature_buffer: List[str] = []
    signature_start = 0
    inside = False
    current_name = ""
    current_start = 0
    depth = 0
    body_lines: List[str] = []

    func_name_re = re.compile(
        r"""(?:^|[\s\*\)])([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:\{|$)"""
    )

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not inside:
            if not signature_buffer:
                signature_start = idx

            # Ignore préprocesseur et typedef.
            if stripped.startswith("#") or stripped.startswith("typedef"):
                signature_buffer = []
                continue

            signature_buffer.append(line)
            joined = "\n".join(signature_buffer).strip()

            # Évite les buffers immenses.
            if len(signature_buffer) > 8 or ";" in joined and "{" not in joined:
                signature_buffer = []
                continue

            if "{" not in joined:
                continue

            before_brace = joined.split("{", 1)[0]
            if "=" in before_brace and "(" not in before_brace:
                signature_buffer = []
                continue

            match = func_name_re.search(joined)
            if not match:
                signature_buffer = []
                continue

            name = match.group(1)
            if name in control_keywords:
                signature_buffer = []
                continue

            inside = True
            current_name = name
            current_start = signature_start
            body_lines = signature_buffer.copy()
            depth = sum(brace_delta(x) for x in signature_buffer)
            signature_buffer = []

            if depth <= 0:
                text = "\n".join(body_lines)
                functions[current_name] = FunctionBlock(
                    current_name,
                    current_start,
                    idx,
                    text,
                    normalize_code(text),
                    len(body_lines),
                )
                inside = False
                current_name = ""
                current_start = 0
                body_lines = []
                depth = 0
            continue

        body_lines.append(line)
        depth += brace_delta(line)

        if depth <= 0:
            text = "\n".join(body_lines)
            functions[current_name] = FunctionBlock(
                current_name,
                current_start,
                idx,
                text,
                normalize_code(text),
                len(body_lines),
            )
            inside = False
            current_name = ""
            current_start = 0
            body_lines = []
            depth = 0

    return functions


def classify_line_tags(a_lines: Sequence[str], b_lines: Sequence[str]) -> Tuple[List[str], List[str]]:
    """
    Tags visuels:
      exact   = ligne incluse dans un bloc exact
      changed = ligne proche/modifiée
      unique  = ligne propre au fichier
    """
    a_tags = ["unique"] * len(a_lines)
    b_tags = ["unique"] * len(b_lines)

    matcher = difflib.SequenceMatcher(None, a_lines, b_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for i in range(i1, i2):
                a_tags[i] = "exact"
            for j in range(j1, j2):
                b_tags[j] = "exact"
        elif tag == "replace":
            for i in range(i1, i2):
                a_tags[i] = "changed"
            for j in range(j1, j2):
                b_tags[j] = "changed"
        elif tag == "delete":
            for i in range(i1, i2):
                a_tags[i] = "unique"
        elif tag == "insert":
            for j in range(j1, j2):
                b_tags[j] = "unique"

    return a_tags, b_tags


def ansi_line(line: str, tag: str) -> str:
    if tag == "exact":
        return f"{ANSI_GREEN}{line}{ANSI_RESET}"
    if tag == "changed":
        return f"{ANSI_YELLOW}{line}{ANSI_RESET}"
    return f"{ANSI_RED}{line}{ANSI_RESET}"


def html_line(line: str, tag: str, number: int) -> str:
    esc = html.escape(line)
    return (
        f'<div class="line {tag}">'
        f'<span class="num">{number:5d}</span>'
        f'<span class="code">{esc if esc else " "}</span>'
        f'</div>'
    )


def similarity_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def build_text_report(
    file_a: Path,
    file_b: Path,
    a_lines: Sequence[str],
    b_lines: Sequence[str],
    funcs_a: Dict[str, FunctionBlock],
    funcs_b: Dict[str, FunctionBlock],
    exact_blocks: Sequence[MatchBlock],
    normalized_blocks: Sequence[MatchBlock],
) -> str:
    a_nonempty = non_empty(a_lines)
    b_nonempty = non_empty(b_lines)

    exact_order = lcs_order_count(a_lines, b_lines)
    exact_any_order = multiset_intersection_count(a_lines, b_lines)
    exact_nonempty_any_order = multiset_intersection_count(a_nonempty, b_nonempty)

    a_norm_nonempty = [normalize_line(x) for x in a_lines if normalize_line(x)]
    b_norm_nonempty = [normalize_line(x) for x in b_lines if normalize_line(x)]
    norm_any_order = multiset_intersection_count(a_norm_nonempty, b_norm_nonempty)

    common_funcs = sorted(set(funcs_a) & set(funcs_b))
    only_a_funcs = sorted(set(funcs_a) - set(funcs_b))
    only_b_funcs = sorted(set(funcs_b) - set(funcs_a))

    out: List[str] = []
    out.append("=" * 78)
    out.append("RAPPORT TECHNIQUE DE SIMILARITE DE CODE")
    out.append("=" * 78)
    out.append("")
    out.append(f"Date analyse       : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    out.append(f"Fichier A/original : {file_a}")
    out.append(f"Fichier B/modifie  : {file_b}")
    out.append("")
    out.append("-" * 78)
    out.append("1) RESUME CHIFFRE")
    out.append("-" * 78)
    out.append(f"Lignes A totales                         : {len(a_lines)}")
    out.append(f"Lignes B totales                         : {len(b_lines)}")
    out.append(f"Lignes A non vides                       : {count_nonempty(a_lines)}")
    out.append(f"Lignes B non vides                       : {count_nonempty(b_lines)}")
    out.append("")
    out.append(f"Lignes exactes A retrouvees dans B, meme ordre : "
               f"{exact_order}/{len(a_lines)} = {pct(exact_order, len(a_lines)):.2f}%")
    out.append(f"Lignes exactes A retrouvees dans B, ordre ignore: "
               f"{exact_any_order}/{len(a_lines)} = {pct(exact_any_order, len(a_lines)):.2f}%")
    out.append(f"Lignes non vides A retrouvees textuellement dans B: "
               f"{exact_nonempty_any_order}/{len(a_nonempty)} = {pct(exact_nonempty_any_order, len(a_nonempty)):.2f}%")
    out.append(f"Lignes normalisees communes hors commentaires/espaces: "
               f"{norm_any_order}/{len(a_norm_nonempty)} = {pct(norm_any_order, len(a_norm_nonempty)):.2f}%")
    out.append("")
    out.append(f"Blocs exacts continus >= 3 lignes         : {len(exact_blocks)}")
    out.append(f"Total lignes dans blocs exacts           : {sum(b.size for b in exact_blocks)}")
    out.append(f"Blocs normalises continus >= 3 lignes    : {len(normalized_blocks)}")
    out.append(f"Total lignes dans blocs normalises       : {sum(b.size for b in normalized_blocks)}")
    out.append("")
    out.append(f"Fonctions A detectees                    : {len(funcs_a)}")
    out.append(f"Fonctions B detectees                    : {len(funcs_b)}")
    out.append(f"Fonctions communes par nom               : {len(common_funcs)}")
    out.append(f"Fonctions seulement dans A               : {len(only_a_funcs)}")
    out.append(f"Fonctions seulement dans B               : {len(only_b_funcs)}")
    out.append("")
    out.append("Lecture rapide:")
    if len(b_lines) > len(a_lines) * 2 and pct(exact_order, len(a_lines)) >= 50:
        out.append("- Le fichier B semble etre une extension importante du fichier A.")
        out.append("- Une part significative de A est reprise, mais B contient aussi beaucoup d'ajouts.")
    elif pct(exact_order, len(a_lines)) >= 80:
        out.append("- Le fichier B est tres proche du fichier A.")
    elif pct(exact_order, len(a_lines)) >= 40:
        out.append("- Le fichier B partage une base importante avec A.")
    else:
        out.append("- Les fichiers partagent une base limitee ou tres modifiee.")
    out.append("- Ce rapport ne remplace pas une verification de licence/attribution.")
    out.append("")

    out.append("-" * 78)
    out.append("2) FONCTIONS COMMUNES ET TAUX DE SIMILARITE")
    out.append("-" * 78)
    if not common_funcs:
        out.append("Aucune fonction commune detectee par nom.")
    else:
        for name in common_funcs:
            fa = funcs_a[name]
            fb = funcs_b[name]
            ratio_raw = similarity_ratio(fa.text, fb.text) * 100
            ratio_norm = similarity_ratio(fa.normalized_text, fb.normalized_text) * 100
            if ratio_norm >= 98:
                status = "quasi identique"
            elif ratio_norm >= 80:
                status = "fortement similaire"
            elif ratio_norm >= 50:
                status = "modifiee mais reliee"
            else:
                status = "fortement remaniee"
            out.append(
                f"- {name}: A lignes {fa.start}-{fa.end} ({fa.line_count} lignes), "
                f"B lignes {fb.start}-{fb.end} ({fb.line_count} lignes), "
                f"similarite brute {ratio_raw:.2f}%, normalisee {ratio_norm:.2f}% -> {status}"
            )
    out.append("")

    out.append("-" * 78)
    out.append("3) FONCTIONS AJOUTEES DANS B")
    out.append("-" * 78)
    if only_b_funcs:
        for name in only_b_funcs:
            fb = funcs_b[name]
            out.append(f"- {name}: lignes {fb.start}-{fb.end}, {fb.line_count} lignes")
    else:
        out.append("Aucune fonction ajoutee detectee dans B.")
    out.append("")

    out.append("-" * 78)
    out.append("4) FONCTIONS ABSENTES DE B MAIS PRESENTES DANS A")
    out.append("-" * 78)
    if only_a_funcs:
        for name in only_a_funcs:
            fa = funcs_a[name]
            out.append(f"- {name}: lignes {fa.start}-{fa.end}, {fa.line_count} lignes")
    else:
        out.append("Aucune fonction de A ne manque dans B par nom.")
    out.append("")

    out.append("-" * 78)
    out.append("5) BLOCS EXACTS CONTINUS")
    out.append("-" * 78)
    if not exact_blocks:
        out.append("Aucun bloc exact >= 3 lignes.")
    else:
        for n, block in enumerate(exact_blocks, start=1):
            out.append(
                f"Bloc exact #{n}: A lignes {block.a_start}-{block.a_start + block.size - 1} "
                f"<=> B lignes {block.b_start}-{block.b_start + block.size - 1} "
                f"({block.size} lignes)"
            )
    out.append("")

    out.append("-" * 78)
    out.append("6) BLOCS NORMALISES CONTINUS")
    out.append("-" * 78)
    out.append("Normalise = comparaison en ignorant commentaires et differences d'espaces.")
    if not normalized_blocks:
        out.append("Aucun bloc normalise >= 3 lignes.")
    else:
        for n, block in enumerate(normalized_blocks, start=1):
            out.append(
                f"Bloc normalise #{n}: A lignes {block.a_start}-{block.a_start + block.size - 1} "
                f"<=> B lignes {block.b_start}-{block.b_start + block.size - 1} "
                f"({block.size} lignes)"
            )
    out.append("")

    out.append("-" * 78)
    out.append("7) FORMULATION PRUDENTE POUR DOSSIER / README")
    out.append("-" * 78)
    out.append(
        "Formulation conseillee si B derive de A:\n"
        "\"Ce projet est base sur le travail initial de [auteur/projet]. "
        "Il conserve certaines parties communes, mais ajoute une extension significative: "
        "nouvelles fonctions, nouveaux modes, systeme de logs, detection/configuration, "
        "et adaptations specifiques. Les parties d'origine restent creditees conformement "
        "a la licence du projet initial.\""
    )
    out.append("")
    out.append(
        "Attention: si la licence originale impose attribution, conservation de licence, "
        "ou redistribution sous la meme licence, le rapport technique ne permet pas de "
        "supprimer ces obligations."
    )
    out.append("")

    return "\n".join(out)


def build_ansi_report(
    title: str,
    lines: Sequence[str],
    tags: Sequence[str],
    max_lines: int | None = None,
) -> str:
    out = []
    out.append(f"{ANSI_BOLD}{title}{ANSI_RESET}")
    out.append("Legende: vert = repris exact, jaune = modifie/proche, rouge = unique")
    out.append("")
    limit = len(lines) if max_lines is None else min(len(lines), max_lines)
    for idx in range(limit):
        num = f"{idx + 1:5d} | "
        out.append(num + ansi_line(lines[idx], tags[idx]))
    if limit < len(lines):
        out.append(f"... {len(lines) - limit} lignes non affichees ...")
    return "\n".join(out)


def build_html_report(
    file_a: Path,
    file_b: Path,
    text_report: str,
    a_lines: Sequence[str],
    b_lines: Sequence[str],
    a_tags: Sequence[str],
    b_tags: Sequence[str],
) -> str:
    a_html = "\n".join(html_line(line, tag, i + 1) for i, (line, tag) in enumerate(zip(a_lines, a_tags)))
    b_html = "\n".join(html_line(line, tag, i + 1) for i, (line, tag) in enumerate(zip(b_lines, b_tags)))

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>Rapport similarite code</title>
<style>
    body {{
        margin: 0;
        font-family: Arial, sans-serif;
        background: #111827;
        color: #e5e7eb;
    }}
    header {{
        padding: 18px 24px;
        background: #020617;
        border-bottom: 1px solid #334155;
        position: sticky;
        top: 0;
        z-index: 10;
    }}
    h1 {{ margin: 0 0 8px 0; font-size: 22px; }}
    .legend span {{
        display: inline-block;
        padding: 4px 8px;
        margin-right: 8px;
        border-radius: 6px;
        font-size: 13px;
    }}
    .exactKey {{ background: #14532d; }}
    .changedKey {{ background: #854d0e; }}
    .uniqueKey {{ background: #7f1d1d; }}
    .wrap {{
        padding: 18px 24px;
    }}
    pre.summary {{
        white-space: pre-wrap;
        background: #020617;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        overflow: auto;
        line-height: 1.35;
    }}
    .grid {{
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 14px;
        align-items: start;
    }}
    .panel {{
        border: 1px solid #334155;
        border-radius: 10px;
        overflow: hidden;
        background: #020617;
    }}
    .panel h2 {{
        margin: 0;
        padding: 10px 12px;
        background: #0f172a;
        font-size: 16px;
        border-bottom: 1px solid #334155;
    }}
    .codebox {{
        font-family: Consolas, Monaco, monospace;
        font-size: 12px;
        line-height: 1.35;
        overflow: auto;
        max-height: 82vh;
    }}
    .line {{
        display: grid;
        grid-template-columns: 64px 1fr;
        min-height: 18px;
        white-space: pre;
    }}
    .line .num {{
        color: #94a3b8;
        background: rgba(15,23,42,.85);
        border-right: 1px solid #334155;
        text-align: right;
        padding-right: 8px;
        user-select: none;
    }}
    .line .code {{
        padding-left: 8px;
    }}
    .line.exact {{ background: rgba(22, 101, 52, .72); }}
    .line.changed {{ background: rgba(161, 98, 7, .72); }}
    .line.unique {{ background: rgba(127, 29, 29, .72); }}
    @media (max-width: 1100px) {{
        .grid {{ grid-template-columns: 1fr; }}
    }}
</style>
</head>
<body>
<header>
    <h1>Rapport de similarité de code</h1>
    <div class="legend">
        <span class="exactKey">Vert: repris exactement</span>
        <span class="changedKey">Jaune: modifié / proche</span>
        <span class="uniqueKey">Rouge: unique au fichier</span>
    </div>
</header>
<div class="wrap">
    <h2>Résumé technique</h2>
    <pre class="summary">{html.escape(text_report)}</pre>
    <h2>Comparaison visuelle complète</h2>
    <div class="grid">
        <section class="panel">
            <h2>A / original — {html.escape(str(file_a))}</h2>
            <div class="codebox">{a_html}</div>
        </section>
        <section class="panel">
            <h2>B / modifié — {html.escape(str(file_b))}</h2>
            <div class="codebox">{b_html}</div>
        </section>
    </div>
</div>
</body>
</html>
"""


def analyze(file_a: Path, file_b: Path, outdir: Path, min_block: int) -> Tuple[Path, Path, Path]:
    text_a = read_text_file(file_a)
    text_b = read_text_file(file_b)
    a_lines = split_lines_keep(text_a)
    b_lines = split_lines_keep(text_b)

    funcs_a = extract_c_functions(a_lines)
    funcs_b = extract_c_functions(b_lines)

    exact_blocks = find_exact_blocks(a_lines, b_lines, min_block=min_block)
    normalized_blocks = find_normalized_blocks(a_lines, b_lines, min_block=min_block)

    a_tags, b_tags = classify_line_tags(a_lines, b_lines)

    text_report = build_text_report(
        file_a,
        file_b,
        a_lines,
        b_lines,
        funcs_a,
        funcs_b,
        exact_blocks,
        normalized_blocks,
    )

    outdir.mkdir(parents=True, exist_ok=True)
    txt_path = outdir / "similarity_report.txt"
    ansi_path = outdir / "similarity_report_ansi.txt"
    html_path = outdir / "similarity_report.html"

    txt_path.write_text(text_report, encoding="utf-8")

    ansi = []
    ansi.append(text_report)
    ansi.append("\n\n" + "=" * 78 + "\n")
    ansi.append(build_ansi_report("FICHIER A COLORE", a_lines, a_tags))
    ansi.append("\n\n" + "=" * 78 + "\n")
    ansi.append(build_ansi_report("FICHIER B COLORE", b_lines, b_tags))
    ansi_path.write_text("\n".join(ansi), encoding="utf-8")

    html_report = build_html_report(file_a, file_b, text_report, a_lines, b_lines, a_tags, b_tags)
    html_path.write_text(html_report, encoding="utf-8")

    return txt_path, ansi_path, html_path


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare deux fichiers source et genere un rapport de similarite."
    )
    parser.add_argument("files", nargs="*", help="Deux fichiers a comparer")
    parser.add_argument(
        "--outdir",
        default=None,
        help="Dossier de sortie. Par defaut: dossier du deuxieme fichier.",
    )
    parser.add_argument(
        "--min-block",
        type=int,
        default=3,
        help="Taille minimale des blocs identiques a lister. Defaut: 3 lignes.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)

    if len(args.files) != 2:
        print("ERREUR: glisse exactement 2 fichiers sur ce script.")
        print("")
        print("Usage:")
        print("  python code_similarity_reporter.py original.c modifie.c")
        print("  ou glisse les 2 fichiers directement sur le .py")
        input("\nAppuie sur Entree pour fermer...")
        return 2

    file_a = Path(args.files[0]).expanduser().resolve()
    file_b = Path(args.files[1]).expanduser().resolve()

    if not file_a.is_file():
        print(f"ERREUR: fichier introuvable: {file_a}")
        input("\nAppuie sur Entree pour fermer...")
        return 2
    if not file_b.is_file():
        print(f"ERREUR: fichier introuvable: {file_b}")
        input("\nAppuie sur Entree pour fermer...")
        return 2

    outdir = Path(args.outdir).expanduser().resolve() if args.outdir else file_b.parent / "similarity_report_output"

    print("Analyse en cours...")
    print(f"A/original: {file_a}")
    print(f"B/modifie : {file_b}")
    print(f"Sortie    : {outdir}")

    try:
        txt_path, ansi_path, html_path = analyze(file_a, file_b, outdir, args.min_block)
    except Exception as exc:
        print(f"ERREUR pendant l'analyse: {exc}")
        input("\nAppuie sur Entree pour fermer...")
        return 1

    print("")
    print("OK, rapports crees:")
    print(f"- TXT normal : {txt_path}")
    print(f"- TXT couleur ANSI terminal : {ansi_path}")
    print(f"- HTML couleur navigateur   : {html_path}")
    print("")
    print("Conseil: ouvre surtout le HTML pour voir les couleurs.")
    if os.name == "nt":
        try:
            os.startfile(html_path)  # type: ignore[attr-defined]
        except Exception:
            pass

    input("\nAppuie sur Entree pour fermer...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
