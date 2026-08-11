#!/usr/bin/env python3
"""CLI enrolment helper for pam-totp-lab TOTP modules."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import pwd
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote, urlencode

DEFAULT_ISSUER = "pam-totp-lab"
DEFAULT_SECRET_FILE = ".google_authenticator"
SECRET_BYTES = 20
PERIOD = 30
DIGITS = 6
WINDOW = 1
MAX_ATTEMPTS = 3


def generate_secret() -> str:
    """Return a 160-bit Base32 secret without padding."""
    raw = secrets.token_bytes(SECRET_BYTES)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _decode_base32(secret: str) -> bytes:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(secret + padding, casefold=False)


def totp_at(secret: str, when: int | float, digits: int = DIGITS) -> str:
    """Generate an RFC 6238 SHA-1 TOTP for a Unix timestamp."""
    counter = int(when) // PERIOD
    key = _decode_base32(secret)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % (10 ** digits):0{digits}d}"


def verify_totp(secret: str, candidate: str, now: int | float | None = None) -> bool:
    """Verify a six-digit TOTP in the same +/- one-step window as the lab module."""
    if len(candidate) != DIGITS or not candidate.isascii() or not candidate.isdigit():
        return False
    current = time.time() if now is None else now
    for offset in range(-WINDOW, WINDOW + 1):
        expected = totp_at(secret, current + offset * PERIOD)
        if hmac.compare_digest(expected, candidate):
            return True
    return False


def build_otpauth_uri(secret: str, issuer: str, account: str) -> str:
    """Build a standards-compatible otpauth URI for authenticator applications."""
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": str(DIGITS),
            "period": str(PERIOD),
        }
    )
    return f"otpauth://totp/{label}?{query}"


def show_qr(uri: str) -> None:
    """Render the enrolment URI as a terminal QR without exposing it in argv."""
    if shutil.which("qrencode") is None:
        raise RuntimeError("no se encontró 'qrencode'; instala el paquete qrencode")
    subprocess.run(
        ["qrencode", "-t", "ANSIUTF8"],
        input=uri,
        text=True,
        check=True,
    )


def write_secret(path: Path, secret: str, force: bool = False) -> None:
    """Atomically persist a secret with mode 0600, refusing accidental replacement."""
    path = path.expanduser()
    parent = path.parent
    if not parent.is_dir():
        raise RuntimeError(f"el directorio destino no existe: {parent}")

    try:
        st = path.lstat()
    except FileNotFoundError:
        st = None

    if st is not None and not force:
        raise FileExistsError(f"ya existe {path}; usa --force sólo si quieres rotarlo")
    if st is not None and path.is_dir():
        raise IsADirectoryError(str(path))

    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as handle:
            fd = -1
            handle.write(secret)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        os.chmod(path, 0o600)
        try:
            dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            dir_fd = None
        if dir_fd is not None:
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def default_account() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enrola un TOTP móvil y crea ~/.google_authenticator tras verificarlo."
    )
    parser.add_argument("--issuer", default=DEFAULT_ISSUER, help="issuer mostrado en la app")
    parser.add_argument("--account", default=default_account(), help="cuenta mostrada en la app")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.home() / DEFAULT_SECRET_FILE,
        help="archivo de secreto (por defecto: ~/.google_authenticator)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="reemplaza un secreto existente después de verificar el nuevo TOTP",
    )
    return parser.parse_args(argv)


def _validate_text(value: str, field: str) -> None:
    if not value or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{field} no puede estar vacío ni contener caracteres de control")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        _validate_text(args.issuer, "issuer")
        _validate_text(args.account, "account")

        if args.output.expanduser().exists() and not args.force:
            raise FileExistsError(
                f"ya existe {args.output.expanduser()}; no se ha generado un secreto nuevo"
            )

        secret = generate_secret()
        uri = build_otpauth_uri(secret, args.issuer, args.account)

        print("Escanea este QR con una aplicación TOTP compatible:\n")
        show_qr(uri)
        print("\nEl secreto aún NO se ha guardado en disco.")

        verified = False
        for attempt in range(1, MAX_ATTEMPTS + 1):
            candidate = getpass.getpass(
                f"Código TOTP de {DIGITS} dígitos ({attempt}/{MAX_ATTEMPTS}): "
            ).strip()
            if verify_totp(secret, candidate):
                verified = True
                break
            print("Código no válido.", file=sys.stderr)

        if not verified:
            print("Enrolamiento cancelado: no se escribió ningún secreto.", file=sys.stderr)
            return 2

        write_secret(args.output, secret, force=args.force)
        print(f"Enrolamiento verificado. Secreto guardado en {args.output.expanduser()} (0600).")
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
