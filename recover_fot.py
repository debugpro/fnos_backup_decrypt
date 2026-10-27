#!/usr/bin/env python3
"""Recover fnOS backup_cloud v1 .fot files with their backup password.

Derived from static analysis of fnOS 1.2.0800 backup_cloud. Validate against a
real backup before relying on it for disaster recovery.
"""

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import os
from pathlib import Path
import struct
import tempfile
import unicodedata

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:
    raise SystemExit("cryptography is required: python3 -m pip install cryptography") from exc


MAGIC = b"FOT\xa3\x1cw\x00^"
SALT_PREFIX = bytes.fromhex("3ca15ef9d2076b")
USABILITY_MARKER = b"teirenfeiniuyunpanbeifencryptoencrypto"
VERSION = 1
TAG_LENGTH = 16


class FotError(ValueError):
    pass


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    worker = cipher.decryptor()
    return worker.update(data) + worker.finalize()


def derive_key(password: bytes, random_salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, SALT_PREFIX + random_salt, rounds, 32)


def parse_header(handle):
    prefix = handle.read(19)
    if len(prefix) != 19 or prefix[:8] != MAGIC:
        raise FotError("not a supported FOT file")
    if prefix[8] != VERSION:
        raise FotError(f"unsupported FOT version {prefix[8]}")
    header_len = struct.unpack_from(">H", prefix, 9)[0]
    total_len = struct.unpack_from(">Q", prefix, 11)[0]
    if header_len < 45 or total_len < header_len + TAG_LENGTH:
        raise FotError("invalid FOT length fields")
    header = prefix + handle.read(header_len - 19)
    if len(header) != header_len:
        raise FotError("truncated FOT header")
    iv = header[19:35]
    random_salt = header[35:44]
    fields = {}
    offset = 45
    while offset < header_len:
        if header_len - offset < 3:
            raise FotError("truncated FOT metadata field")
        field_len = struct.unpack_from(">H", header, offset)[0]
        key_len = header[offset + 2]
        if field_len < key_len + 3 or offset + field_len > header_len:
            raise FotError("invalid FOT metadata field length")
        key = header[offset + 3:offset + 3 + key_len].decode("ascii")
        fields[key] = header[offset + 3 + key_len:offset + field_len]
        offset += field_len
    return header_len, total_len, iv, random_salt, fields


def decode_field(value: bytes) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as exc:
        raise FotError("invalid base64 FOT metadata") from exc


def check_password(fields, password: bytes, random_salt: bytes):
    if "usability" not in fields:
        return
    blob = decode_field(fields["usability"])
    if len(blob) < 16:
        raise FotError("truncated password check field")
    marker = aes_ctr(derive_key(password, random_salt, 100), blob[:16], blob[16:])
    if not hmac.compare_digest(marker, USABILITY_MARKER):
        raise FotError("wrong backup password or damaged password check field")


def original_name(fields, password: bytes, random_salt: bytes, iv: bytes):
    if "filename" not in fields:
        return None
    blob = decode_field(fields["filename"])
    if len(blob) < TAG_LENGTH:
        raise FotError("truncated encrypted filename")
    encrypted, tag = blob[:-TAG_LENGTH], blob[-TAG_LENGTH:]
    key = derive_key(password, random_salt, 1000)
    expected = hmac.new(key, encrypted, hashlib.sha256).digest()[:TAG_LENGTH]
    if not hmac.compare_digest(tag, expected):
        raise FotError("wrong backup password or damaged filename")
    try:
        return aes_ctr(key, iv, encrypted).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FotError("invalid UTF-8 filename") from exc


def safe_name(name: str) -> str:
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        raise FotError(f"unsafe original filename: {name!r}")
    return name


def inspect_file(source: Path, password: bytes):
    with source.open("rb") as infile:
        header_len, total_len, iv, random_salt, fields = parse_header(infile)
        if source.stat().st_size != total_len:
            raise FotError("FOT file size does not match its header")
        check_password(fields, password, random_salt)
        name = original_name(fields, password, random_salt, iv)
        if name is None:
            raise FotError("FOT file has no original filename")
        return safe_name(name), total_len - header_len - TAG_LENGTH


def decrypt(source: Path, destination: Path, password: bytes, announce: bool = True):
    if destination.exists():
        raise FotError(f"output already exists: {destination}")
    with source.open("rb") as infile:
        header_len, total_len, iv, random_salt, fields = parse_header(infile)
        if source.stat().st_size != total_len:
            raise FotError("FOT file size does not match its header")
        check_password(fields, password, random_salt)
        name = original_name(fields, password, random_salt, iv)
        if name is not None:
            safe_name(name)
        key = derive_key(password, random_salt, 10000)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        mac = hmac.new(key, digestmod=hashlib.sha256)
        remain = total_len - header_len - TAG_LENGTH
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".fot-recovery-", dir=destination.parent, delete=False) as outfile:
                temporary = Path(outfile.name)
                while remain:
                    encrypted = infile.read(min(remain, 1024 * 1024))
                    if not encrypted:
                        raise FotError("truncated encrypted content")
                    mac.update(encrypted)
                    outfile.write(cipher.update(encrypted))
                    remain -= len(encrypted)
                outfile.write(cipher.finalize())
            tag = infile.read(TAG_LENGTH)
            if len(tag) != TAG_LENGTH or not hmac.compare_digest(tag, mac.digest()[:TAG_LENGTH]):
                raise FotError("content integrity check failed")
            os.link(temporary, destination)  # Fails if destination appeared meanwhile.
            if announce:
                print(f"Restored: {destination}")
                if name is not None:
                    print(f"Original filename: {name}")
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def verify(source: Path, password: bytes):
    with source.open("rb") as infile:
        header_len, total_len, iv, random_salt, fields = parse_header(infile)
        if source.stat().st_size != total_len:
            raise FotError("FOT file size does not match its header")
        check_password(fields, password, random_salt)
        name = original_name(fields, password, random_salt, iv)
        key = derive_key(password, random_salt, 10000)
        mac = hmac.new(key, digestmod=hashlib.sha256)
        remain = total_len - header_len - TAG_LENGTH
        while remain:
            encrypted = infile.read(min(remain, 1024 * 1024))
            if not encrypted:
                raise FotError("truncated encrypted content")
            mac.update(encrypted)
            remain -= len(encrypted)
        tag = infile.read(TAG_LENGTH)
        if len(tag) != TAG_LENGTH or not hmac.compare_digest(tag, mac.digest()[:TAG_LENGTH]):
            raise FotError("content integrity check failed")
    print(f"Verified: {source}")
    if name is not None:
        print(f"Original filename: {name}")


def recover_directory(source: Path, destination: Path, password: bytes, dry_run: bool, skip_existing: bool):
    if destination.resolve().is_relative_to(source.resolve()):
        raise FotError("output directory must be outside the encrypted source directory")
    if destination.exists() and not destination.is_dir():
        raise FotError(f"output path is not a directory: {destination}")
    files = sorted(p for p in source.rglob("*") if p.is_file() and p.suffix.lower() == ".fot")
    if not files:
        raise FotError("no .fot files found in source directory")

    planned = []
    problems = []
    seen = {}
    total_bytes = 0
    for encrypted in files:
        try:
            if encrypted.is_symlink():
                raise FotError("source file is a symbolic link")
            name, size = inspect_file(encrypted, password)
            output = destination / encrypted.relative_to(source).parent / name
            # macOS volumes commonly compare filenames without case or Unicode-form distinctions.
            collision_key = unicodedata.normalize("NFD", str(output)).casefold()
            if collision_key in seen:
                raise FotError(f"output name collides with {seen[collision_key]}")
            seen[collision_key] = encrypted
            if output.exists() and not output.is_file():
                raise FotError(f"output path is not a file: {output}")
            if output.exists() and not skip_existing:
                raise FotError(f"output already exists: {output}")
            planned.append((encrypted, output, size, output.exists()))
            if not output.exists():
                total_bytes += size
        except (FotError, OSError) as exc:
            problems.append((encrypted, str(exc)))

    print(f"Found {len(files)} .fot files; ready {len(planned)}; problems {len(problems)}")
    print(f"New output bytes: {total_bytes:,}")
    for encrypted, issue in problems[:20]:
        print(f"Problem: {encrypted}: {issue}")
    if len(problems) > 20:
        print(f"... and {len(problems) - 20} more problems")
    if problems:
        raise FotError("preflight found problems; no files were written")
    if dry_run:
        for encrypted, output, _, existing in planned[:10]:
            print(f"{encrypted} -> {output}" + (" (skip existing)" if existing else ""))
        if len(planned) > 10:
            print(f"... and {len(planned) - 10} more files")
        return

    failed = []
    restored = skipped = 0
    for index, (encrypted, output, _, existing) in enumerate(planned, 1):
        if existing:
            skipped += 1
            continue
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            decrypt(encrypted, output, password, announce=False)
            restored += 1
        except (FotError, OSError) as exc:
            failed.append((encrypted, str(exc)))
            print(f"Failed: {encrypted}: {exc}")
        if index % 100 == 0 or index == len(planned):
            print(f"Progress: {index}/{len(planned)}; restored {restored}; skipped {skipped}; failed {len(failed)}")
    if failed:
        raise FotError(f"{len(failed)} files failed; rerun with --skip-existing after fixing the cause")
    if skipped:
        print("Existing outputs were skipped without checking their contents.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="encrypted .fot file or a directory containing .fot files")
    parser.add_argument("destination", type=Path, nargs="?", help="output file for one .fot, or output directory for a source directory")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--info", action="store_true", help="inspect the FOT header without a password")
    modes.add_argument("--verify", action="store_true", help="verify password and integrity without writing a recovered file")
    parser.add_argument("--dry-run", action="store_true", help="preview a directory recovery without writing files")
    parser.add_argument("--skip-existing", action="store_true", help="skip existing outputs during directory recovery (contents are not checked)")
    args = parser.parse_args()
    try:
        if args.info:
            if args.source.is_dir():
                raise FotError("--info needs one .fot file")
            with args.source.open("rb") as handle:
                header_len, total_len, iv, random_salt, fields = parse_header(handle)
            print(f"FOT v{VERSION}; total bytes: {total_len}; header bytes: {header_len}")
            print("Metadata fields:", ", ".join(sorted(fields)) or "none")
        elif args.verify:
            if args.source.is_dir():
                raise FotError("--verify needs one .fot file")
            verify(args.source, getpass.getpass("Backup password: ").encode("utf-8"))
        elif args.source.is_dir():
            if args.destination is None:
                parser.error("output directory is required for a source directory")
            recover_directory(args.source, args.destination, getpass.getpass("Backup password: ").encode("utf-8"), args.dry_run, args.skip_existing)
        else:
            if args.dry_run or args.skip_existing:
                parser.error("--dry-run and --skip-existing are for directory recovery only")
            password = getpass.getpass("Backup password: ").encode("utf-8")
            destination = args.destination
            if destination is None:
                name, _ = inspect_file(args.source, password)
                destination = args.source.parent / name
            decrypt(args.source, destination, password)
    except (FotError, OSError) as exc:
        parser.exit(1, f"Recovery failed: {exc}\n")


if __name__ == "__main__":
    main()
