import argparse
import asyncio
import sys

from ps4debug import PS4Debug
from ps4debug.core import VMProtection


PORT = 744
TEXT_FILE_OFFSET = 0x4000
PAGE_SIZE = 0x4000
SUPPORTED_FW_LABEL = "6.02"
EXIT_UNSUPPORTED = 20
EXIT_ERROR = 1

PATCHES = (
    {
        "name": "getApp0DirPath isDebuggerOrAppHome gate",
        "file_offset": 0x004D790C,
        "original": bytes.fromhex("0f 84 87 00 00 00"),
        "patched": b"\x90" * 6,
    },
    {
        "name": "getSceSysDirPath isDebuggerOrAppHome gate",
        "file_offset": 0x004D7BEC,
        "original": bytes.fromhex("0f 84 86 00 00 00"),
        "patched": b"\x90" * 6,
    },
)


class RawVMProtection:
    def __init__(self, value):
        self.value = int(value)


class ShellcoreBaseError(RuntimeError):
    def __init__(self, message, attempts):
        super().__init__(message)
        self.attempts = attempts


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


def hex_bytes(data):
    if data is None:
        return "<none>"
    return bytes(data).hex(" ")


def diff_hex(actual, expected):
    if actual is None:
        return "<none>"
    actual = bytes(actual)
    expected = bytes(expected)
    out = []
    for index, (a, e) in enumerate(zip(actual, expected)):
        marker = "==" if a == e else "!="
        out.append(f"{index:02d}:{a:02x}{marker}{e:02x}")
    if len(actual) != len(expected):
        out.append(f"len:{len(actual)}!={len(expected)}")
    return " ".join(out)


def align_down(value, align):
    return value & ~(align - 1)


def prot_to_vm(prot):
    try:
        return VMProtection(prot)
    except ValueError:
        return RawVMProtection(prot & int(VMProtection.VM_PROT_ALL))


async def find_shellcore_pid(ps5, forced_pid):
    if forced_pid is not None:
        return forced_pid, None

    processes = await ps5.get_processes()
    best = None
    for proc in processes:
        pid = int(field(proc, "pid", 0))
        try:
            info = await ps5.get_process_info(pid)
        except Exception:
            continue

        name = clean(field(info, "name")) or clean(field(proc, "name"))
        path = clean(field(info, "path"))
        joined = f"{name} {path}".lower()
        if "sceshellcore" in joined:
            best = (pid, info)
            break

    if best is None:
        raise RuntimeError("SceShellCore introuvable. Verifie que PS5Debug est actif.")
    return best


async def read_patch_bytes(ps5, pid, base):
    rows = []
    for patch in PATCHES:
        delta = patch["file_offset"] - TEXT_FILE_OFFSET
        addr = base + delta
        current = await ps5.read_memory(pid, addr, len(patch["original"]))
        rows.append((patch, addr, bytes(current) if current is not None else None))
    return rows


async def find_shellcore_base(ps5, pid, maps):
    candidates = []
    for m in maps:
        name = clean(field(m, "name"))
        start = int(field(m, "start", 0))
        end = int(field(m, "end", 0))
        prot = int(field(m, "prot", 0))
        size = end - start
        if not (prot & int(VMProtection.VM_PROT_EXECUTE)):
            continue
        if size < (PATCHES[-1]["file_offset"] - TEXT_FILE_OFFSET + 0x1000):
            continue
        candidates.append((m, name, start, end, prot, size))

    preferred = [
        item for item in candidates
        if "sceshellcore" in item[1].lower() or "shellcore" in item[1].lower()
    ]
    ordered = preferred + [item for item in candidates if item not in preferred]

    attempts = []
    for m, name, start, end, prot, size in ordered:
        try:
            rows = await read_patch_bytes(ps5, pid, start)
        except Exception as exc:
            attempts.append((name, start, end, prot, f"read erreur {type(exc).__name__}: {exc}"))
            continue

        score = 0
        for patch, _addr, data in rows:
            if data == patch["original"] or data == patch["patched"]:
                score += 1

        attempts.append((name, start, end, prot, ", ".join(hex_bytes(row[2]) for row in rows)))
        if score == len(PATCHES):
            return m, rows, attempts

    raise ShellcoreBaseError(
        "Base SceShellCore non trouvee avec les bytes attendus. "
        "Patch refuse: signature FW 6.02 non valide, ShellCore introuvable, "
        "ou PS5Debug pas pret.",
        attempts,
    )


async def set_protection(ps5, pid, address, length, prot):
    page = align_down(address, PAGE_SIZE)
    end = address + length
    page_len = align_down(end + PAGE_SIZE - 1, PAGE_SIZE) - page
    return await ps5.change_protection(pid, page, page_len, prot)


async def main():
    parser = argparse.ArgumentParser(
        description="Check/patch temporairement les gates LNC uniquement quand la signature FW 6.02 est valide."
    )
    parser.add_argument("host", nargs="?", default="192.168.1.131")
    parser.add_argument("--port", type=int, default=PORT, help="Port PS5Debug/ps4debug.")
    parser.add_argument("--pid", type=int, help="PID SceShellCore force, sinon auto-detecte.")
    parser.add_argument(
        "--mode",
        choices=("check", "patch", "restore"),
        default="check",
        help="check lit seulement, patch met les NOP en RAM, restore remet les bytes originaux.",
    )
    parser.add_argument("--debug-diff", action="store_true", help="Affiche un detail PC des bytes attendus/lus.")
    parser.add_argument("--force", action="store_true", help="Ecrit meme si les bytes lus ne correspondent pas.")
    args = parser.parse_args()

    ps5 = PS4Debug(args.host, args.port)
    print(f"[connect] {args.host}:{args.port}")
    print(f"[support] patch PS5 valide seulement pour la signature FW {SUPPORTED_FW_LABEL}")
    try:
        print(f"[version] {await ps5.get_version()}")
    except Exception as exc:
        print(f"[version] erreur {type(exc).__name__}: {exc}")

    pid, info = await find_shellcore_pid(ps5, args.pid)
    if info is None:
        try:
            info = await ps5.get_process_info(pid)
        except Exception:
            info = None

    if info is not None:
        print(
            f"[shellcore] pid={pid} name={clean(field(info, 'name'))} "
            f"path={clean(field(info, 'path'))}"
        )
    else:
        print(f"[shellcore] pid={pid}")

    maps = await ps5.get_process_maps(pid)
    print(f"[maps] count={len(maps)}")

    try:
        base_map, rows, attempts = await find_shellcore_base(ps5, pid, maps)
    except Exception as exc:
        print(f"[base] erreur {type(exc).__name__}: {exc}")
        print(f"[result] STOP: patch non applique. Firmware/signature non supporte ou ShellCore non pret.")
        if args.debug_diff and isinstance(exc, ShellcoreBaseError):
            print("[debug-diff] essais de base executable")
            for name, start, end, prot, observed in exc.attempts:
                print(
                    f"  map={name or '<anon>'} start=0x{start:016x} "
                    f"end=0x{end:016x} prot=0x{prot:x} observed={observed}"
                )
        print("[candidate maps]")
        for m in maps:
            name = clean(field(m, "name"))
            start = int(field(m, "start", 0))
            end = int(field(m, "end", 0))
            prot = int(field(m, "prot", 0))
            if prot & int(VMProtection.VM_PROT_EXECUTE):
                print(f"  {name:36} 0x{start:016x}-0x{end:016x} prot=0x{prot:x}")
        return EXIT_UNSUPPORTED

    base = int(field(base_map, "start", 0))
    prot = int(field(base_map, "prot", 0))
    print(
        f"[base] 0x{base:016x} prot=0x{prot:x} "
        f"name={clean(field(base_map, 'name'))}"
    )

    all_ok = True
    already_patched = True
    for patch, addr, data in rows:
        status = "unknown"
        if data == patch["original"]:
            status = "original"
            already_patched = False
        elif data == patch["patched"]:
            status = "patched"
        else:
            all_ok = False
            already_patched = False
        print(
            f"[check] {patch['name']} file=0x{patch['file_offset']:08x} "
            f"addr=0x{addr:016x} bytes={hex_bytes(data)} status={status}"
        )
        if args.debug_diff:
            print(f"[debug-diff] {patch['name']}")
            print(f"  expected_original={hex_bytes(patch['original'])}")
            print(f"  expected_patched ={hex_bytes(patch['patched'])}")
            print(f"  actual           ={hex_bytes(data)}")
            print(f"  diff_vs_original={diff_hex(data, patch['original'])}")
            print(f"  diff_vs_patched ={diff_hex(data, patch['patched'])}")

    if args.mode == "check":
        if all_ok:
            print("[result] OK: les deux branches sont localisees. Mode patch possible.")
            return 0
        else:
            print("[result] STOP: bytes inattendus, ne patch pas sans revoir la sortie.")
            return EXIT_UNSUPPORTED

    target_key = "patched" if args.mode == "patch" else "original"
    expected_key = "original" if args.mode == "patch" else "patched"
    if args.mode == "patch" and already_patched:
        print("[result] deja patche.")
        return 0

    writes = []
    for patch, addr, data in rows:
        expected = patch[expected_key]
        target = patch[target_key]
        if data != expected and not args.force:
            print(
                f"[stop] {patch['name']} attendu={hex_bytes(expected)} "
                f"lu={hex_bytes(data)}. Utilise --force seulement si tu es sur."
            )
            return EXIT_UNSUPPORTED
        writes.append((patch, addr, target))

    first_addr = min(addr for _patch, addr, _target in writes)
    last_addr = max(addr + len(target) for _patch, addr, target in writes)
    print("[protect] RWX temporaire")
    print(await set_protection(ps5, pid, first_addr, last_addr - first_addr, VMProtection.VM_PROT_ALL))

    for patch, addr, target in writes:
        result = await ps5.write_memory(pid, addr, target)
        print(f"[write] {patch['name']} addr=0x{addr:016x} -> {hex_bytes(target)} result={result}")

    print("[protect] restore protection")
    print(await set_protection(ps5, pid, first_addr, last_addr - first_addr, prot_to_vm(prot)))

    print("[verify]")
    rows = await read_patch_bytes(ps5, pid, base)
    ok = True
    for patch, addr, data in rows:
        expected = patch[target_key]
        match = data == expected
        ok = ok and match
        print(f"  addr=0x{addr:016x} bytes={hex_bytes(data)} match={match}")

    if ok:
        print(f"[result] {args.mode} OK")
        return 0
    else:
        print(f"[result] {args.mode} incomplet")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
