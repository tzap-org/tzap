#!/usr/bin/env python3
"""Check the OpenSSL linkage and archive round trip of a TZAP release package."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def check_linkage(binary: Path, target: str) -> None:
    if target.endswith("-msvc"):
        dependencies = subprocess.check_output(["dumpbin", "/dependents", binary], text=True)
    elif target.endswith("-apple-darwin"):
        dependencies = subprocess.check_output(["otool", "-L", binary], text=True)
    else:
        dependencies = subprocess.check_output(["readelf", "-d", binary], text=True)
        if "(NEEDED)" in dependencies:
            raise SystemExit(f"Expected a static musl executable:\n{dependencies}")
    if re.search(r"\blib(?:crypto|ssl)\b", dependencies, re.IGNORECASE):
        raise SystemExit(f"Found a shared OpenSSL dependency:\n{dependencies}")


def smoke(binary: Path, work: Path, version: str, emulator: str) -> None:
    command = [emulator, binary] if emulator else [binary]

    def tzap(*arguments, password=None, capture=False):
        return subprocess.run(
            [*command, *arguments], input=password, text=True, check=True,
            stdout=subprocess.PIPE if capture else None,
        ).stdout

    reported = json.loads(tzap("trust-info", "--json", capture=True))["openssl_version"]
    if reported.split()[:2] != ["OpenSSL", version]:
        raise SystemExit(f"Expected OpenSSL {version}, got {reported}")
    print(reported, flush=True)
    tzap("--version")
    tzap("--help")

    source = work / "input.txt"
    source.write_bytes(b"release smoke payload\n")
    archive = work / "smoke.tzap"
    out = work / "out"
    password = "release-smoke-passphrase\n"
    tzap(
        "create", "--password-stdin", "--argon2-t-cost", "1", "--argon2-m-cost-kib", "8",
        "--argon2-parallelism", "1", "-o", archive, source, password=password,
    )
    listing = tzap("list", "--password-stdin", archive, password=password, capture=True)
    if source.name not in listing:
        raise SystemExit(f"Missing {source.name} from release smoke listing")
    tzap("verify", "--password-stdin", archive, password=password)
    tzap("extract", "--password-stdin", "--directory", out, archive, source.name, password=password)
    if source.read_bytes() != (out / source.name).read_bytes():
        raise SystemExit("Release smoke payload mismatch")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("target")
    parser.add_argument("--emulator", default="")
    parser.add_argument("--inspect-only", action="store_true")
    args = parser.parse_args()

    bootstrap = Path(__file__).with_name("build-openssl.py")
    version = subprocess.check_output([sys.executable, bootstrap, "--version"], text=True).strip()
    windows = args.target.endswith("-msvc")
    # Windows can keep the executable mapped after the smoke test exits.
    with tempfile.TemporaryDirectory(prefix="tzap-release-smoke-", ignore_cleanup_errors=windows) as temp:
        work = Path(temp)
        package = work / "package"
        shutil.unpack_archive(args.archive, package)
        notice = (package / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
        license_text = (package / "OPENSSL-LICENSE.txt").read_text(encoding="utf-8")
        if f"OpenSSL {version} (Apache-2.0)." not in notice or "Apache License" not in license_text:
            raise SystemExit(f"Missing OpenSSL {version} notice or upstream license")

        binary = package / ("tzap.exe" if windows else "tzap")
        check_linkage(binary, args.target)
        if args.inspect_only:
            # The Windows x64 runner cannot execute the ARM64 binary. This string
            # comes from the libcrypto implementation of OpenSSL_version().
            if f"OpenSSL {version} ".encode("ascii") not in binary.read_bytes():
                raise SystemExit(f"Missing the OpenSSL {version} version string in {binary.name}")
            print(f"OpenSSL {version} linked statically")
        else:
            smoke(binary, work, version, args.emulator)


if __name__ == "__main__":
    main()
