#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import subprocess


ROOT = pathlib.Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {".py", ".js", ".html", ".css", ".md", ".yml", ".yaml", ".json", ".sh", ".txt", ".conf"}


def repository_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / value for value in result.stdout.splitlines() if (ROOT / value).is_file()]


def main() -> int:
    files = repository_files()
    forbidden = [
        path.relative_to(ROOT).as_posix()
        for path in files
        if path.name == ".env" or path.suffix.lower() in {".pfx", ".p12", ".key"}
    ]
    if forbidden:
        raise SystemExit(f"forbidden secret-bearing files are tracked: {', '.join(forbidden)}")

    legacy_name = "pc" + "-client"
    private_key_pattern = re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
    subscription_pattern = re.compile(r"https?://[^\s\"']+/sub/[A-Za-z0-9_-]{20,}")
    findings: list[str] = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile", ".dockerignore", ".env.example"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(content.splitlines(), 1):
            if private_key_pattern.search(line) or subscription_pattern.search(line):
                findings.append(f"{relative}:{number}: possible secret")
            if legacy_name in line:
                allowed_migration = relative == "api/app.py" and "WHERE key = 'github.repository'" in line
                if not allowed_migration:
                    findings.append(f"{relative}:{number}: legacy repository name")
    if findings:
        raise SystemExit("repository guard failed:\n" + "\n".join(findings))
    print(f"repository guard passed for {len(files)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
