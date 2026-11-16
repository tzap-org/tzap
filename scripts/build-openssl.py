#!/usr/bin/env python3
"""Build a checksum-pinned static OpenSSL for TZAP."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlopen


VERSION = "3.5.9"
SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
RELEASE = f"https://github.com/openssl/openssl/releases/download/openssl-{VERSION}/openssl-{VERSION}.tar.gz"
RSA_PSS_ALIAS_BACKPORT = "https://github.com/openssl/openssl/commit/af2aaf3271c0b0a193f33d5c0be07754b846759e"
TARGETS = {
    "aarch64-apple-darwin": "darwin64-arm64-cc",
    "x86_64-apple-darwin": "darwin64-x86_64-cc",
    "aarch64-unknown-linux-gnu": "linux-aarch64",
    "x86_64-unknown-linux-gnu": "linux-x86_64",
    "aarch64-unknown-linux-musl": "linux-aarch64",
    "x86_64-unknown-linux-musl": "linux-x86_64",
    "aarch64-pc-windows-msvc": "VC-WIN64-ARM",
    "x86_64-pc-windows-msvc": "VC-WIN64A",
}


def native_build(target: str, install: Path, work: Path) -> None:
    archive = work / "openssl.tar.gz"
    digest = hashlib.sha256()
    with urlopen(RELEASE, timeout=60) as response, archive.open("wb") as output:
        for chunk in iter(lambda: response.read(1024 * 1024), b""):
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != SHA256:
        raise ValueError("OpenSSL release tarball failed SHA-256 verification")

    env = os.environ.copy()
    target_env = target.replace("-", "_")
    for name in ("CC", "AR", "RANLIB"):
        compiler = env.get(f"{name}_{target_env}")
        if compiler:
            env[name] = compiler

    subprocess.run(["tar", "-xf", str(archive)], cwd=work, check=True, stdout=sys.stderr)
    source = work / f"openssl-{VERSION}"
    # OpenSSL 3.5.9 can cache an empty RSA-PSS decoder list if X.509 decoding
    # races with legacy name registration. Backport the upstream provider alias.
    names_header = source / "providers/implementations/include/prov/names.h"
    names = names_header.read_bytes()
    original = b'#define PROV_NAMES_RSA_PSS "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10"'
    replacement = (
        b"/* TZAP backport of the upstream rsassaPss provider alias. */\n"
        b'#define PROV_NAMES_RSA_PSS "RSA-PSS:RSASSA-PSS:rsassaPss:1.2.840.113549.1.1.10"'
    )
    if names.count(original) != 1:
        raise ValueError("OpenSSL source does not match the RSA-PSS alias backport")
    names_header.write_bytes(names.replace(original, replacement))

    windows = target.endswith("-msvc")
    openssl_dir = "SYS$MANAGER:[OPENSSL]" if windows else "/usr/local/ssl"
    configure = [
        env.get("OPENSSL_SRC_PERL") or env.get("PERL") or "perl",
        "Configure",
        TARGETS[target],
        f"--prefix={install.as_posix()}",
        f"--openssldir={openssl_dir}",
        "--libdir=lib",
        "no-shared",
        "no-module",
        "no-tests",
    ]
    if windows:
        configure += ["no-asm", "no-capieng"]
    if target.endswith("-musl"):
        configure += ["no-engine", "no-async", "-DOPENSSL_NO_SECURE_MEMORY"]

    def run(arguments) -> None:
        subprocess.run(arguments, cwd=source, env=env, check=True, stdout=sys.stderr)

    run(configure)
    make = ["nmake"] if windows else ["make", "-j", str(min(os.cpu_count() or 1, 8))]
    run([*make, "build_libs"])
    run([*make, "install_dev"])
    shutil.copyfile(source / "LICENSE.txt", install / "OPENSSL-LICENSE.txt")
    (install / "THIRD-PARTY-NOTICES.txt").write_text(
        f"This TZAP binary statically links OpenSSL {VERSION} (Apache-2.0).\n"
        f"Source: {RELEASE}\n"
        f"TZAP backport (RSA-PSS provider alias): {RSA_PSS_ALIAS_BACKPORT}\n"
        "See OPENSSL-LICENSE.txt for the upstream license and notices.\n",
        encoding="utf-8",
    )


def provision(target: str, root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    prefix = root / target
    windows = target.endswith("-msvc")
    libraries = ["libssl.lib", "libcrypto.lib"] if windows else ["libssl.a", "libcrypto.a"]
    version_header = Path("include/openssl/opensslv.h")
    notice = Path("THIRD-PARTY-NOTICES.txt")
    expected = [
        version_header,
        Path("OPENSSL-LICENSE.txt"),
        notice,
        *(Path("lib") / name for name in libraries),
    ]

    def complete(path: Path) -> bool:
        if not all((path / item).is_file() for item in expected):
            return False
        if RSA_PSS_ALIAS_BACKPORT not in (path / notice).read_text(encoding="utf-8"):
            return False
        header = (path / version_header).read_text(encoding="utf-8")
        return re.search(rf'^# *define +OPENSSL_VERSION_STR +"{re.escape(VERSION)}"$', header, re.MULTILINE) is not None

    if complete(prefix):
        return prefix
    if prefix.exists():
        raise ValueError(f"incomplete OpenSSL installation at {prefix}")
    with tempfile.TemporaryDirectory(dir=root, prefix=f"{target}-") as work_dir:
        work = Path(work_dir)
        install = work / "install"
        native_build(target, install, work)
        if not complete(install):
            raise ValueError("OpenSSL did not install the expected static libraries")
        try:
            install.rename(prefix)
        except OSError:
            if not complete(prefix):
                raise
    return prefix


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "target" / "tzap-openssl" / f"{VERSION}-r1",
        help="installation root containing the per-target directories",
    )
    parser.add_argument("target", choices=TARGETS)
    args = parser.parse_args()
    try:
        print(provision(args.target, args.root.resolve()))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"OpenSSL {VERSION} build failed: {error}\n")


if __name__ == "__main__":
    main()
