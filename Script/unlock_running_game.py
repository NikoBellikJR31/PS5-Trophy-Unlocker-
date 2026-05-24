import argparse
import asyncio
import ftplib
import io
import re
import sys
from pathlib import Path

from ps4debug import PS4Debug


NPCOMM_RE = re.compile(rb"NPWR\d{5}_\d{2}")
NPTITLE_RE = re.compile(r"(?:PPSA|CUSA)\d{5}")
USER_HOME_RE = re.compile(r"^[0-9a-fA-F]{8}$")


def field(obj, name, default=""):
    try:
        return getattr(obj, name)
    except Exception:
        try:
            return obj[name]
        except Exception:
            return default


def clean(value):
    if value is None:
        return ""
    text = str(value)
    if "\x00" in text:
        text = text.split("\x00", 1)[0]
    return text.strip()


def describe(row):
    pid, name, title_id, content_id, path = row
    content = content_id if content_id else "-"
    title = title_id if title_id else "-"
    return f"pid={pid} name={name} title={title} content={content} path={path}"


def score_game_process(row):
    pid, name, title_id, content_id, path = row
    lname = name.lower()
    lpath = path.lower()

    score = 0
    if lname == "eboot.bin":
        score += 100
    if path == "/app0/eboot.bin":
        score += 50
    if content_id:
        score += 40
    if title_id:
        score += 20
    if "npxs" in content_id.lower() or "/system/" in lpath:
        score -= 100
    if lname.startswith("sce"):
        score -= 40
    if "elfldr" in lname or "payload" in lname or "ftpsrv" in lname:
        score -= 100
    return score


def parse_ftp_ports(text):
    ports = []
    for part in (text or "").replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ports.append(int(part))
        except ValueError:
            pass
    return ports


def title_candidates(row):
    _, _, title_id, content_id, _ = row
    seen = set()
    out = []

    for text in (title_id, content_id):
        for match in NPTITLE_RE.findall(text or ""):
            if match not in seen:
                seen.add(match)
                out.append(match)

    clean_title = clean(title_id)
    if clean_title.isdigit() and len(clean_title) == 5:
        for prefix in ("PPSA", "CUSA"):
            value = prefix + clean_title
            if value not in seen:
                seen.add(value)
                out.append(value)

    return out


def detect_platform(row):
    _, _, title_id, content_id, _ = row
    text = f"{title_id or ''} {content_id or ''}".upper()

    if "CUSA" in text:
        return "ps4"
    if "PPSA" in text:
        return "ps5"
    return ""


def ftp_download(host, port, path):
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=8)
    ftp.login()
    data = io.BytesIO()
    ftp.retrbinary(f"RETR {path}", data.write)
    try:
        ftp.quit()
    except Exception:
        ftp.close()
    return data.getvalue()


def ftp_list_names(host, port, path):
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=8)
    ftp.login()
    try:
        names = ftp.nlst(path)
    except Exception:
        lines = []
        ftp.retrlines(f"LIST {path}", lines.append)
        names = [line.split()[-1] for line in lines if line.split()]
    try:
        ftp.quit()
    except Exception:
        ftp.close()

    cleaned = []
    for name in names:
        clean_name = str(name).rstrip("/").split("/")[-1]
        if clean_name and clean_name not in (".", ".."):
            cleaned.append(clean_name)
    return cleaned


def ftp_upload_text(host, port, remote_name, text):
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=8)
    ftp.login()
    data = io.BytesIO(text.encode("ascii"))
    ftp.storbinary(f"STOR /data/{remote_name}", data)
    try:
        ftp.quit()
    except Exception:
        ftp.close()


def ftp_upload_bytes(host, port, remote_name, payload):
    ftp = ftplib.FTP()
    ftp.connect(host, port, timeout=8)
    ftp.login()
    data = io.BytesIO(payload)
    ftp.storbinary(f"STOR /data/{remote_name}", data)
    try:
        ftp.quit()
    except Exception:
        ftp.close()


def extract_npcomm(blob):
    match = NPCOMM_RE.search(blob)
    if not match:
        return ""
    return match.group(0).decode("ascii")


def _add_signature_candidate(candidates, seen, name, payload):
    if len(payload) != 160 or payload == b"\x00" * 160:
        return
    if payload in seen:
        return
    seen.add(payload)
    candidates.append((name, payload))


def extract_ps4_signature_candidates_from_npbind(blob):
    candidates = []
    seen = set()

    for offset in range(0, max(0, len(blob) - 4)):
        tag = int.from_bytes(blob[offset:offset + 2], "big")
        size = int.from_bytes(blob[offset + 2:offset + 4], "big")
        if tag != 0x0012 or size < 160 or size > 512:
            continue
        end = offset + 4 + size
        if end > len(blob):
            continue

        value = blob[offset + 4:end]
        _add_signature_candidate(
            candidates, seen, f"npbind_tag12_off0x{offset:x}_first160",
            value[:160],
        )
        _add_signature_candidate(
            candidates, seen, f"npbind_tag12_off0x{offset:x}_last160",
            value[-160:],
        )
        if len(value) >= 176:
            _add_signature_candidate(
                candidates, seen, f"npbind_tag12_off0x{offset:x}_skip16",
                value[16:176],
            )

    return candidates


def extract_ps4_signature_candidates_from_nptitle(blob):
    candidates = []
    seen = set()
    if len(blob) >= 0xA0 and blob[:4] == b"NPTD":
        _add_signature_candidate(
            candidates, seen, "nptitle_off0x20_len128_pad",
            blob[0x20:0xA0].ljust(160, b"\x00"),
        )
    return candidates


def parse_trptitle_count(blob):
    if len(blob) < 0x180:
        return 0
    if blob[0:4] != b"T2PD" or blob[0x40:0x44] != b"T2TD":
        return 0

    count_a = int.from_bytes(blob[0x11C:0x120], "big")
    count_b = int.from_bytes(blob[0x17C:0x180], "big")
    for count in (count_a, count_b):
        if 0 < count <= 128:
            return count
    return 0


def find_npcomm_and_ps4_sigs_over_ftp(host, ports, row):
    candidates = title_candidates(row)
    if not candidates:
        print("[npcomm] aucun title id dans le process")
        return "", []

    suffixes = (
        "/system_data/priv/appmeta/{title}/npbind.dat",
        "/system_data/priv/appmeta/{title}/trophy2/npbind.dat",
        "/system_data/priv/appmeta/{title}/trophy/npbind.dat",
        "/system_data/priv/appmeta/{title}/uds/npbind.dat",
        "/mnt/sandbox/pfsmnt/{title}-app0-patch0-union/sce_sys/trophy2/npbind.dat",
        "/mnt/sandbox/pfsmnt/{title}-app0-patch0-union/sce_sys/trophy/npbind.dat",
        "/mnt/sandbox/pfsmnt/{title}-app0-patch0-union/sce_sys/uds/npbind.dat",
        "/mnt/sandbox/pfsmnt/{title}-app0/sce_sys/trophy2/npbind.dat",
        "/mnt/sandbox/pfsmnt/{title}-app0/sce_sys/trophy/npbind.dat",
        "/mnt/sandbox/pfsmnt/{title}-app0/sce_sys/uds/npbind.dat",
    )

    for port in ports:
        for title in candidates:
            for template in suffixes:
                path = template.format(title=title)
                try:
                    blob = ftp_download(host, port, path)
                except Exception:
                    continue

                npcomm = extract_npcomm(blob)
                if npcomm:
                    print(f"[npcomm] {title} via ftp:{port}{path} -> {npcomm}")
                    sigs = extract_ps4_signature_candidates_from_npbind(blob)

                    nptitle_path = f"/system_data/priv/appmeta/{title}/nptitle.dat"
                    try:
                        nptitle = ftp_download(host, port, nptitle_path)
                        extra = extract_ps4_signature_candidates_from_nptitle(nptitle)
                        if extra:
                            print(f"[npsig] {title} via ftp:{port}{nptitle_path} -> {len(extra)} candidat(s)")
                            sigs.extend(extra)
                    except Exception:
                        pass

                    if sigs:
                        labels = ", ".join(name for name, _ in sigs)
                        print(f"[npsig] candidats={len(sigs)} {labels}")
                    else:
                        print("[npsig] aucun candidat signature PS4 trouve")
                    return npcomm, sigs

    print(f"[npcomm] introuvable via FTP pour {', '.join(candidates)}")
    return "", []


def find_npcomm_over_ftp(host, ports, row):
    npcomm, _ = find_npcomm_and_ps4_sigs_over_ftp(host, ports, row)
    return npcomm


def find_trptitle_count_over_ftp(host, ports, npcomm):
    for port in ports:
        try:
            homes = ftp_list_names(host, port, "/user/home/")
        except Exception as exc:
            print(f"[count] liste /user/home ftp:{port} echoue: {type(exc).__name__}: {exc}")
            continue

        for home in homes:
            if not USER_HOME_RE.fullmatch(home):
                continue
            path = f"/user/home/{home}/trophy2/nobackup/data/{npcomm}/TRPTITLE.DAT"
            try:
                blob = ftp_download(host, port, path)
            except Exception:
                continue

            count = parse_trptitle_count(blob)
            if count:
                print(f"[count] {npcomm} via ftp:{port}{path} -> {count}")
                return count

    print(f"[count] TRPTITLE introuvable via FTP pour {npcomm}")
    return 0


def prepare_npcomm_override(host, ports, row, remote_name, count_name, npsig_name):
    if not ports:
        return

    npcomm, sigs = find_npcomm_and_ps4_sigs_over_ftp(host, ports, row)
    if not npcomm:
        return

    npcomm_uploaded = False
    for port in ports:
        try:
            ftp_upload_text(host, port, remote_name, npcomm)
            print(f"[npcomm] /data/{remote_name} <- {npcomm} via ftp:{port}")
            npcomm_uploaded = True
            break
        except Exception as exc:
            print(f"[npcomm] upload ftp:{port} echoue: {type(exc).__name__}: {exc}")

    if not npcomm_uploaded:
        return

    if sigs:
        payload = b"".join(sig for _, sig in sigs[:8])
        for port in ports:
            try:
                ftp_upload_bytes(host, port, npsig_name, payload)
                print(f"[npsig] /data/{npsig_name} <- {len(payload)} bytes ({len(payload) // 160} candidat(s)) via ftp:{port}")
                break
            except Exception as exc:
                print(f"[npsig] upload ftp:{port} echoue: {type(exc).__name__}: {exc}")

    count = find_trptitle_count_over_ftp(host, ports, npcomm)
    if not count:
        return

    for port in ports:
        try:
            ftp_upload_text(host, port, count_name, str(count))
            print(f"[count] /data/{count_name} <- {count} via ftp:{port}")
            return
        except Exception as exc:
            print(f"[count] upload ftp:{port} echoue: {type(exc).__name__}: {exc}")


def prepare_platform_override(host, ports, row, platform_name):
    if not ports or not platform_name:
        return

    platform = detect_platform(row)
    if not platform:
        print("[platform] type PS4/PS5 introuvable depuis ps5debug")
        return

    for port in ports:
        try:
            ftp_upload_text(host, port, platform_name, platform)
            print(f"[platform] /data/{platform_name} <- {platform} via ftp:{port}")
            return
        except Exception as exc:
            print(f"[platform] upload ftp:{port} echoue: {type(exc).__name__}: {exc}")


async def collect_process_rows(ps5):
    processes = await ps5.get_processes()
    rows = []

    for proc in processes:
        pid = int(field(proc, "pid", 0))
        fallback_name = clean(field(proc, "name"))
        try:
            info = await ps5.get_process_info(pid)
        except Exception:
            info = None

        if info is None:
            rows.append((pid, fallback_name, "", "", ""))
            continue

        rows.append((
            pid,
            clean(field(info, "name")) or fallback_name,
            clean(field(info, "title_id")),
            clean(field(info, "content_id")),
            clean(field(info, "path")),
        ))

    return rows


async def collect_process_rows_fast(ps5):
    processes = await ps5.get_processes()
    rows = []

    for proc in processes:
        pid = int(field(proc, "pid", 0))
        fallback_name = clean(field(proc, "name"))

        # The real game process is normally named eboot.bin. Querying process
        # info for every /app0 service makes ps5debug unstable on some setups,
        # so keep the fast path narrow.
        if fallback_name.lower() != "eboot.bin":
            continue

        try:
            info = await ps5.get_process_info(pid)
        except Exception:
            rows.append((pid, fallback_name, "", "", ""))
            continue

        rows.append((
            pid,
            clean(field(info, "name")) or fallback_name,
            clean(field(info, "title_id")),
            clean(field(info, "content_id")),
            clean(field(info, "path")),
        ))

    return rows


async def main():
    parser = argparse.ArgumentParser(
        description="Find the running PS5 game process and inject trophy_unlocker.elf."
    )
    parser.add_argument("host", help="PS5 IP address")
    parser.add_argument("--port", type=int, default=744, help="PS5Debug port")
    parser.add_argument(
        "--elf",
        default=str(Path(__file__).with_name("trophy_unlocker.elf")),
        help="ELF to inject",
    )
    parser.add_argument("--pid", type=int, default=0, help="Manual PID override")
    parser.add_argument("--list", action="store_true", help="List candidates only")
    parser.add_argument(
        "--ftp-ports",
        default="",
        help="Comma-separated FTP ports used to prepare /data/trophy_unlocker_npcomm.txt",
    )
    parser.add_argument(
        "--npcomm-name",
        default="trophy_unlocker_npcomm.txt",
        help="Remote /data filename for the NPWR override",
    )
    parser.add_argument(
        "--count-name",
        default="trophy_unlocker_count.txt",
        help="Remote /data filename for the trophy count override",
    )
    parser.add_argument(
        "--npsig-name",
        default="trophy_unlocker_npsig.bin",
        help="Remote /data filename for PS4 communication signature candidates",
    )
    parser.add_argument(
        "--platform-name",
        default="trophy_unlocker_platform.txt",
        help="Remote /data filename used to force the PS4/PS5 route",
    )
    parser.add_argument("--no-npcomm", action="store_true", help="Do not prepare NPWR override")
    args = parser.parse_args()

    elf_path = Path(args.elf)
    if not elf_path.exists():
        print(f"[error] ELF introuvable: {elf_path}")
        return 2

    ps5 = PS4Debug(args.host, args.port)
    print(f"[connect] {args.host}:{args.port}")

    try:
        version = await ps5.get_version()
        print(f"[version] {version}")
    except Exception as exc:
        print(f"[error] PS5Debug ne repond pas: {type(exc).__name__}: {exc}")
        return 3

    if args.list:
        rows = await collect_process_rows(ps5)
    else:
        rows = await collect_process_rows_fast(ps5)

    game_like = []
    for row in rows:
        pid, name, title_id, content_id, path = row
        if name.lower() == "eboot.bin" or content_id:
            game_like.append(row)

    ranked = sorted(game_like, key=lambda row: (score_game_process(row), row[0]), reverse=True)

    print("[candidates]")
    for row in ranked[:12]:
        print("  " + describe(row))

    if args.list:
        return 0

    if args.pid:
        target_pid = args.pid
        target_row = next((row for row in rows if row[0] == target_pid), None)
    else:
        strong = [row for row in ranked if score_game_process(row) >= 100]
        if not strong:
            print("[error] Aucun jeu eboot.bin fiable. Lance le jeu, active debug, puis relance.")
            return 4
        target_row = strong[0]
        target_pid = target_row[0]

    if target_row is None:
        print(f"[target] pid={target_pid}")
    else:
        print(f"[target] {describe(target_row)}")
        prepare_platform_override(
            args.host,
            parse_ftp_ports(args.ftp_ports),
            target_row,
            args.platform_name,
        )
        if not args.no_npcomm:
            prepare_npcomm_override(
                args.host,
                parse_ftp_ports(args.ftp_ports),
                target_row,
                args.npcomm_name,
                args.count_name,
                args.npsig_name,
            )

    print(f"[elf] {elf_path} ({elf_path.stat().st_size} bytes)")
    print("[load_elf] injection...")

    try:
        status = await ps5.load_elf(target_pid, str(elf_path))
    except Exception as exc:
        print(f"[load_elf] erreur {type(exc).__name__}: {exc}")
        return 5

    print(f"[load_elf] status={status!r}")
    print("[done] ELF envoye au process du jeu.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
