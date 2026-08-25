from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from common.database_lock import database_access


FORMAT_NAME = "vpn-enus-watcher-backup"
FORMAT_VERSION = 2
DATABASE_SCHEMA_GENERATION = 3
SERVICE_VERSION = os.environ.get("LOKI_WATCHER_VERSION", "0.1.0")
STATE_MEMBER = "data/watcher.db.enc"
README_MEMBER = "README.txt"
MANIFEST_MEMBER = "manifest.json"
ALLOWED_MEMBERS = {MANIFEST_MEMBER, STATE_MEMBER, README_MEMBER}
REQUIRED_TABLES = {
    "clients",
    "events",
    "analytics_reports",
    "commands",
    "issued_connections",
    "connection_sources",
    "register_entries",
    "audit_events",
    "watcher_settings",
    "operator_credentials",
}
GENERATION_TWO_REQUIRED_TABLES = REQUIRED_TABLES - {"analytics_reports"}
LEGACY_REQUIRED_TABLES = GENERATION_TWO_REQUIRED_TABLES - {"connection_sources"}
SUPPORTED_DATABASE_SCHEMA_GENERATIONS = frozenset({1, 2, DATABASE_SCHEMA_GENERATION})
MAX_COMPRESSED_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_BACKUP_BYTES", str(128 * 1024 * 1024)))
MAX_UNCOMPRESSED_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_BACKUP_UNCOMPRESSED_BYTES", str(256 * 1024 * 1024)))
MAX_MEMBER_BYTES = int(os.environ.get("LOKI_WATCHER_MAX_BACKUP_MEMBER_BYTES", str(256 * 1024 * 1024)))
MAX_MEMBER_COUNT = 8
MAX_COMPRESSION_RATIO = 100
CHUNK_BYTES = 1024 * 1024
AAD = f"{FORMAT_NAME}:v{FORMAT_VERSION}".encode("ascii")


class BackupContractError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_backup_key(value: str | None = None) -> bytes:
    encoded = (value if value is not None else os.environ.get("LOKI_WATCHER_BACKUP_ENCRYPTION_KEY", "")).strip()
    if not encoded or encoded in {"GENERATED_BY_PREPARE", "CHANGE_ME"}:
        raise BackupContractError("backup_encryption_key_missing")
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * ((4 - len(encoded) % 4) % 4))
    except (ValueError, TypeError) as exc:
        raise BackupContractError("backup_encryption_key_invalid") from exc
    if len(key) != 32:
        raise BackupContractError("backup_encryption_key_invalid")
    return key


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while chunk := source.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_database(source_path: str, target_path: str) -> None:
    source = sqlite3.connect(source_path)
    target = sqlite3.connect(target_path)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(target_path, 0o600)


def required_tables_for_generation(schema_generation: int) -> set[str]:
    if schema_generation == DATABASE_SCHEMA_GENERATION:
        return REQUIRED_TABLES
    if schema_generation == 2:
        return GENERATION_TWO_REQUIRED_TABLES
    if schema_generation == 1:
        return LEGACY_REQUIRED_TABLES
    raise BackupContractError("backup_manifest_incompatible")


def database_record_counts(
    path: str,
    *,
    schema_generation: int = DATABASE_SCHEMA_GENERATION,
) -> dict[str, int]:
    required_tables = required_tables_for_generation(schema_generation)
    db = sqlite3.connect(path)
    try:
        integrity = db.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            raise BackupContractError("backup_database_integrity_failed")
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if not required_tables.issubset(tables):
            raise BackupContractError("backup_database_schema_invalid")
        return {
            table: int(db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in sorted(required_tables)
        }
    except sqlite3.DatabaseError as exc:
        raise BackupContractError("backup_database_invalid") from exc
    finally:
        db.close()


def encrypt_file(source_path: str, target_path: str, key: bytes) -> tuple[str, str]:
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(AAD)
    with open(source_path, "rb") as source, open(target_path, "wb") as target:
        while chunk := source.read(CHUNK_BYTES):
            target.write(encryptor.update(chunk))
        target.write(encryptor.finalize())
    os.chmod(target_path, 0o600)
    return base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="), base64.urlsafe_b64encode(encryptor.tag).decode("ascii").rstrip("=")


def decrypt_file(source_path: str, target_path: str, key: bytes, nonce_value: str, tag_value: str) -> None:
    try:
        nonce = base64.urlsafe_b64decode(nonce_value + "=" * ((4 - len(nonce_value) % 4) % 4))
        tag = base64.urlsafe_b64decode(tag_value + "=" * ((4 - len(tag_value) % 4) % 4))
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(AAD)
        with open(source_path, "rb") as source, open(target_path, "wb") as target:
            while chunk := source.read(CHUNK_BYTES):
                target.write(decryptor.update(chunk))
            target.write(decryptor.finalize())
        os.chmod(target_path, 0o600)
    except (ValueError, InvalidTag) as exc:
        try:
            os.remove(target_path)
        except OSError:
            pass
        raise BackupContractError("backup_decryption_failed") from exc


def readme_text() -> str:
    return (
        "VPNЭНУС Watcher encrypted recovery archive.\n"
        "Timestamps are UTC. Restore mode is complete replacement.\n"
        "The database member is encrypted with AES-256-GCM. The external "
        "LOKI_WATCHER_BACKUP_ENCRYPTION_KEY is required and is not included.\n"
        "The archive may contain client enrollment credentials and subscription secrets only inside ciphertext.\n"
        "Checksums detect corruption; they do not authenticate who created the archive.\n"
    )


def create_backup_archive(db_path: str, archive_path: str, *, source: str, key: bytes | None = None) -> dict[str, Any]:
    key = key or decode_backup_key()
    target_dir = os.path.dirname(os.path.abspath(archive_path)) or "."
    os.makedirs(target_dir, mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target_dir) as temp_dir:
        snapshot_path = os.path.join(temp_dir, "watcher.db")
        encrypted_path = os.path.join(temp_dir, "watcher.db.enc")
        with database_access(db_path):
            snapshot_database(db_path, snapshot_path)
        record_counts = database_record_counts(snapshot_path)
        nonce, tag = encrypt_file(snapshot_path, encrypted_path, key)
        readme = readme_text().encode("utf-8")
        state_size = os.path.getsize(encrypted_path)
        if state_size > MAX_MEMBER_BYTES or state_size + len(readme) > MAX_UNCOMPRESSED_BYTES:
            raise BackupContractError("backup_uncompressed_limit_exceeded")
        manifest = {
            "format": FORMAT_NAME,
            "schemaVersion": FORMAT_VERSION,
            "databaseSchemaGeneration": DATABASE_SCHEMA_GENERATION,
            "serviceRole": "watcher-control-plane",
            "sourceVersion": SERVICE_VERSION,
            "createdAt": utc_now(),
            "scope": "complete",
            "restoreMode": "replace",
            "source": source,
            "encryption": {
                "algorithm": "AES-256-GCM",
                "keyFingerprint": key_fingerprint(key),
                "nonce": nonce,
                "tag": tag,
                "externalKeyRequired": True,
            },
            "files": {
                STATE_MEMBER: {
                    "sha256": sha256_file(encrypted_path),
                    "uncompressedBytes": state_size,
                    "records": sum(record_counts.values()),
                    "recordCounts": record_counts,
                    "encrypted": True,
                },
                README_MEMBER: {
                    "sha256": hashlib.sha256(readme).hexdigest(),
                    "uncompressedBytes": len(readme),
                    "records": 0,
                    "encrypted": False,
                },
            },
        }
        manifest["manifestHmacSha256"] = hmac.new(
            key,
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        pending_path = os.path.join(target_dir, f".{os.path.basename(archive_path)}.{os.urandom(6).hex()}.tmp")
        try:
            with zipfile.ZipFile(pending_path, "w", allowZip64=False) as archive:
                archive.write(encrypted_path, STATE_MEMBER, compress_type=zipfile.ZIP_STORED)
                archive.writestr(README_MEMBER, readme, compress_type=zipfile.ZIP_DEFLATED)
                archive.writestr(MANIFEST_MEMBER, json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), compress_type=zipfile.ZIP_DEFLATED)
            if os.path.getsize(pending_path) > MAX_COMPRESSED_BYTES:
                raise BackupContractError("backup_compressed_limit_exceeded")
            os.chmod(pending_path, 0o600)
            os.replace(pending_path, archive_path)
        finally:
            try:
                os.remove(pending_path)
            except OSError:
                pass
    return manifest


def _safe_member(info: zipfile.ZipInfo) -> bool:
    name = info.filename
    path = PurePosixPath(name)
    mode = info.external_attr >> 16
    return (
        name in ALLOWED_MEMBERS
        and not path.is_absolute()
        and ".." not in path.parts
        and not re.match(r"^[A-Za-z]:", name)
        and not stat.S_ISLNK(mode)
    )


def validate_and_decrypt_archive(archive_path: str, output_db_path: str, *, key: bytes | None = None) -> dict[str, Any]:
    key = key or decode_backup_key()
    if os.path.getsize(archive_path) <= 0 or os.path.getsize(archive_path) > MAX_COMPRESSED_BYTES:
        raise BackupContractError("invalid_backup_size")
    encrypted_path = f"{output_db_path}.enc"
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(infos) > MAX_MEMBER_COUNT or len(names) != len(set(names)):
                raise BackupContractError("backup_member_list_invalid")
            if set(names) != ALLOWED_MEMBERS or any(not _safe_member(info) for info in infos):
                raise BackupContractError("backup_member_list_invalid")
            total_size = 0
            for info in infos:
                if info.file_size > MAX_MEMBER_BYTES:
                    raise BackupContractError("backup_member_too_large")
                total_size += info.file_size
                ratio = info.file_size / max(1, info.compress_size)
                if ratio > MAX_COMPRESSION_RATIO:
                    raise BackupContractError("backup_compression_ratio_exceeded")
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise BackupContractError("backup_uncompressed_limit_exceeded")
            manifest_bytes = archive.read(MANIFEST_MEMBER)
            try:
                manifest = json.loads(manifest_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BackupContractError("backup_manifest_invalid") from exc
            schema_generation = manifest.get("databaseSchemaGeneration")
            if (
                manifest.get("format") != FORMAT_NAME
                or manifest.get("schemaVersion") != FORMAT_VERSION
                or type(schema_generation) is not int
                or schema_generation not in SUPPORTED_DATABASE_SCHEMA_GENERATIONS
                or manifest.get("scope") != "complete"
                or manifest.get("restoreMode") != "replace"
            ):
                raise BackupContractError("backup_manifest_incompatible")
            manifest_mac = manifest.get("manifestHmacSha256")
            unsigned_manifest = {key_name: value for key_name, value in manifest.items() if key_name != "manifestHmacSha256"}
            expected_manifest_mac = hmac.new(
                key,
                json.dumps(unsigned_manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not isinstance(manifest_mac, str) or not hmac.compare_digest(manifest_mac, expected_manifest_mac):
                raise BackupContractError("backup_manifest_authentication_failed")
            encryption = manifest.get("encryption") if isinstance(manifest.get("encryption"), dict) else {}
            if encryption.get("algorithm") != "AES-256-GCM" or encryption.get("keyFingerprint") != key_fingerprint(key):
                raise BackupContractError("backup_encryption_key_mismatch")
            files = manifest.get("files") if isinstance(manifest.get("files"), dict) else {}
            for member in (STATE_MEMBER, README_MEMBER):
                expected = files.get(member) if isinstance(files.get(member), dict) else {}
                data = archive.read(member) if member == README_MEMBER else None
                if expected.get("uncompressedBytes") != archive.getinfo(member).file_size:
                    raise BackupContractError("backup_member_size_mismatch")
                if data is not None and hashlib.sha256(data).hexdigest() != expected.get("sha256"):
                    raise BackupContractError("backup_member_digest_mismatch")
            digest = hashlib.sha256()
            with archive.open(STATE_MEMBER, "r") as source, open(encrypted_path, "wb") as target:
                while chunk := source.read(CHUNK_BYTES):
                    digest.update(chunk)
                    target.write(chunk)
            if digest.hexdigest() != files[STATE_MEMBER].get("sha256"):
                raise BackupContractError("backup_member_digest_mismatch")
        decrypt_file(encrypted_path, output_db_path, key, encryption.get("nonce", ""), encryption.get("tag", ""))
        counts = database_record_counts(output_db_path, schema_generation=schema_generation)
        if counts != files[STATE_MEMBER].get("recordCounts"):
            raise BackupContractError("backup_record_count_mismatch")
        db = sqlite3.connect(output_db_path)
        try:
            if db.execute("PRAGMA foreign_key_check").fetchall():
                raise BackupContractError("backup_foreign_key_check_failed")
        finally:
            db.close()
        return manifest
    except zipfile.BadZipFile as exc:
        raise BackupContractError("invalid_zip") from exc
    finally:
        try:
            os.remove(encrypted_path)
        except OSError:
            pass
