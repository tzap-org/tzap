#!/usr/bin/env python3
"""Run reproducible tzap workflow benchmarks.

The script creates deterministic benchmark data under target/tzap-bench,
runs tzap and any installed comparison tools, then writes CSV and Markdown
tables suitable for public benchmark notes.
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import datetime as dt
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORK_DIR = REPO_ROOT / "target" / "tzap-bench"
BENCH_PASSWORD = "tzap-benchmark-password"


@dataclasses.dataclass(frozen=True)
class DatasetSpec:
    name: str
    selected_relative_path: str


@dataclasses.dataclass
class Measurement:
    seconds: float | None = None
    peak_rss_kib: int | None = None
    note: str = ""


@dataclasses.dataclass
class ResultRow:
    dataset: str
    tool: str
    create_s: float | None = None
    verify_s: float | None = None
    extract_all_s: float | None = None
    extract_one_s: float | None = None
    output_size_bytes: int | None = None
    peak_rss_kib: int | None = None
    status: str = "ok"
    notes: str = ""


@dataclasses.dataclass
class RecoveryRow:
    dataset: str
    scenario: str
    create_s: float | None = None
    recover_verify_s: float | None = None
    output_size_bytes: int | None = None
    status: str = "ok"
    notes: str = ""


class CommandRunner:
    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.gnu_time = find_gnu_time()

    def run(
        self,
        label: str,
        command: list[str],
        *,
        cwd: Path,
        stdout_to_null: bool = False,
    ) -> Measurement:
        safe_label = label.replace("/", "_").replace(" ", "_")
        log_path = self.log_dir / f"{safe_label}.log"
        time_path = self.log_dir / f"{safe_label}.time"
        timed_command = command
        if self.gnu_time is not None:
            timed_command = [
                str(self.gnu_time),
                "-f",
                "peak_rss_kib=%M",
                "-o",
                str(time_path),
                *command,
            ]

        start = time.perf_counter()
        with log_path.open("ab") as log:
            log.write(("\n$ " + shell_join(command) + "\n").encode())
            stdout = subprocess.DEVNULL if stdout_to_null else log
            completed = subprocess.run(
                timed_command,
                cwd=cwd,
                stdout=stdout,
                stderr=log,
                check=False,
            )
        seconds = time.perf_counter() - start
        if completed.returncode != 0:
            raise RuntimeError(
                f"{label} failed with exit {completed.returncode}; see {log_path}"
            )

        return Measurement(seconds=seconds, peak_rss_kib=parse_peak_rss(time_path))


def shell_join(command: Iterable[str]) -> str:
    import shlex

    return " ".join(shlex.quote(part) for part in command)


def shell_quote(path_or_text: object) -> str:
    import shlex

    return shlex.quote(str(path_or_text))


def find_gnu_time() -> Path | None:
    for candidate in ("gtime", "/usr/bin/time"):
        found = shutil.which(candidate) if "/" not in candidate else candidate
        if not found:
            continue
        try:
            probe = subprocess.run(
                [found, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except OSError:
            continue
        if "GNU" in (probe.stdout + probe.stderr):
            return Path(found)
    return None


def parse_peak_rss(path: Path) -> int | None:
    if not path.exists():
        return None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("peak_rss_kib="):
            value = line.split("=", 1)[1].strip()
            return int(value) if value.isdigit() else None
    return None


def deterministic_bytes(size: int, seed: int) -> bytes:
    state = seed & 0xFFFFFFFFFFFFFFFF
    out = bytearray(size)
    for index in range(size):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[index] = (state >> 56) & 0xFF
    return bytes(out)


def write_pattern_file(path: Path, size: int, seed: int, *, texty: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining = size
    with path.open("wb") as handle:
        if texty:
            line = (
                f"tzap benchmark seed={seed} private recoverable archive data\n".encode()
            )
            while remaining > 0:
                chunk = line[: min(len(line), remaining)]
                handle.write(chunk)
                remaining -= len(chunk)
            return

        block_seed = seed
        while remaining > 0:
            block_size = min(64 * 1024, remaining)
            handle.write(deterministic_bytes(block_size, block_seed))
            block_seed += 1
            remaining -= block_size


def create_datasets(root: Path, profile: str) -> list[DatasetSpec]:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    if profile == "smoke":
        many_count, many_size = 64, 1024
        large_size = 8 * 1024 * 1024
        mixed_docs, mixed_media_size = 24, 512 * 1024
    else:
        many_count, many_size = 1500, 4 * 1024
        large_size = 256 * 1024 * 1024
        mixed_docs, mixed_media_size = 400, 4 * 1024 * 1024

    many = root / "many-small"
    for index in range(many_count):
        group = f"group-{index // 100:03d}"
        write_pattern_file(
            many / group / f"file-{index:05d}.txt",
            many_size,
            10_000 + index,
            texty=index % 3 != 0,
        )

    large = root / "large-file"
    write_pattern_file(large / "media" / "archive-image.bin", large_size, 20_000)

    mixed = root / "mixed-backup"
    for index in range(mixed_docs):
        write_pattern_file(
            mixed / "docs" / f"record-{index:04d}.txt",
            2048 + (index % 17) * 83,
            30_000 + index,
            texty=True,
        )
    for index in range(8 if profile == "smoke" else 32):
        write_pattern_file(
            mixed / "media" / f"photo-{index:04d}.bin",
            mixed_media_size,
            40_000 + index,
        )
    write_pattern_file(mixed / "source" / "src" / "main.rs", 32 * 1024, 50_000, texty=True)

    return [
        DatasetSpec("many-small", "group-000/file-00000.txt"),
        DatasetSpec("large-file", "media/archive-image.bin"),
        DatasetSpec("mixed-backup", "docs/record-0000.txt"),
    ]


def build_tzap(skip_build: bool, tzap_path: Path | None) -> Path:
    if tzap_path is not None:
        if not tzap_path.exists():
            raise FileNotFoundError(f"tzap binary not found: {tzap_path}")
        return tzap_path

    binary = REPO_ROOT / "target" / "release" / "tzap"
    if not skip_build:
        subprocess.run(["cargo", "build", "--release", "-p", "tzap"], cwd=REPO_ROOT, check=True)
    if not binary.exists():
        raise FileNotFoundError(
            f"tzap binary not found at {binary}; run cargo build --release -p tzap"
        )
    return binary


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    if path.is_dir():
        return sum(child.stat().st_size for child in path.rglob("*") if child.is_file())
    return 0


def volume_set_size(base: Path) -> int:
    stem = base.name
    if stem.endswith(".tzap"):
        prefix = stem[:-5]
    else:
        prefix = stem
    volumes = sorted(base.parent.glob(f"{prefix}.vol*.tzap"))
    return sum(path.stat().st_size for path in volumes)


def max_rss(*measurements: Measurement) -> int | None:
    values = [m.peak_rss_kib for m in measurements if m.peak_rss_kib is not None]
    return max(values) if values else None


def run_tzap(
    runner: CommandRunner,
    tzap: Path,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.tzap"
    key = output_root / "bench.key"
    restore = restore_root / f"{dataset.name}-tzap"
    remove_path(archive)
    remove_path(restore)
    if not key.exists():
        runner.run("tzap-keygen", [str(tzap), "keygen", "--output", str(key)], cwd=REPO_ROOT)

    create = runner.run(
        f"{dataset.name}/tzap-create",
        [str(tzap), "create", "--keyfile", str(key), "-o", str(archive), dataset.name],
        cwd=data_root,
    )
    verify = runner.run(
        f"{dataset.name}/tzap-verify",
        [str(tzap), "verify", "--keyfile", str(key), str(archive)],
        cwd=data_root,
    )
    extract_all = runner.run(
        f"{dataset.name}/tzap-extract-all",
        [str(tzap), "extract", "--keyfile", str(key), "-C", str(restore), str(archive)],
        cwd=data_root,
    )
    extract_one = runner.run(
        f"{dataset.name}/tzap-extract-one",
        [
            str(tzap),
            "extract",
            "--keyfile",
            str(key),
            "--stdout",
            str(archive),
            f"{dataset.name}/{dataset.selected_relative_path}",
        ],
        cwd=data_root,
        stdout_to_null=True,
    )
    return ResultRow(
        dataset=dataset.name,
        tool="tzap",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=path_size(archive),
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def run_tar_zstd(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.tar.zst"
    restore = restore_root / f"{dataset.name}-tar-zstd"
    remove_path(archive)
    remove_path(restore)
    restore.mkdir(parents=True)
    create_cmd = (
        f"tar -cf - {shell_quote(dataset.name)} | "
        f"zstd -q -T0 -o {shell_quote(archive)} -"
    )
    verify_cmd = f"zstd -q -t {shell_quote(archive)}"
    extract_cmd = (
        f"zstd -q -dc {shell_quote(archive)} | "
        f"tar -xf - -C {shell_quote(restore)}"
    )
    extract_one_cmd = (
        f"zstd -q -dc {shell_quote(archive)} | "
        f"tar -xOf - {shell_quote(dataset.name + '/' + dataset.selected_relative_path)} "
        f"> /dev/null"
    )
    create = runner.run(
        f"{dataset.name}/tar-zstd-create", ["bash", "-lc", create_cmd], cwd=data_root
    )
    verify = runner.run(
        f"{dataset.name}/tar-zstd-verify", ["bash", "-lc", verify_cmd], cwd=data_root
    )
    extract_all = runner.run(
        f"{dataset.name}/tar-zstd-extract-all", ["bash", "-lc", extract_cmd], cwd=data_root
    )
    extract_one = runner.run(
        f"{dataset.name}/tar-zstd-extract-one",
        ["bash", "-lc", extract_one_cmd],
        cwd=data_root,
    )
    return ResultRow(
        dataset=dataset.name,
        tool="tar+zstd",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=path_size(archive),
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def run_tar_zstd_age(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.tar.zst.age"
    identity = output_root / "age-identity.txt"
    restore = restore_root / f"{dataset.name}-tar-zstd-age"
    remove_path(archive)
    remove_path(restore)
    restore.mkdir(parents=True)

    if not identity.exists():
        runner.run(
            "age-keygen",
            ["age-keygen", "-o", str(identity)],
            cwd=data_root,
        )
    public_key = ""
    for line in identity.read_text().splitlines():
        if line.startswith("# public key:"):
            public_key = line.split(":", 1)[1].strip()
            break
    if not public_key:
        raise RuntimeError(f"could not read age public key from {identity}")

    create_cmd = (
        f"tar -cf - {shell_quote(dataset.name)} | "
        f"zstd -q -T0 | "
        f"age -r {shell_quote(public_key)} -o {shell_quote(archive)}"
    )
    verify_cmd = f"age -d -i {shell_quote(identity)} {shell_quote(archive)} | zstd -q -t -"
    extract_cmd = (
        f"age -d -i {shell_quote(identity)} {shell_quote(archive)} | "
        f"zstd -q -dc - | tar -xf - -C {shell_quote(restore)}"
    )
    extract_one_cmd = (
        f"age -d -i {shell_quote(identity)} {shell_quote(archive)} | "
        f"zstd -q -dc - | "
        f"tar -xOf - {shell_quote(dataset.name + '/' + dataset.selected_relative_path)} "
        f"> /dev/null"
    )
    create = runner.run(
        f"{dataset.name}/tar-zstd-age-create", ["bash", "-lc", create_cmd], cwd=data_root
    )
    verify = runner.run(
        f"{dataset.name}/tar-zstd-age-verify", ["bash", "-lc", verify_cmd], cwd=data_root
    )
    extract_all = runner.run(
        f"{dataset.name}/tar-zstd-age-extract-all",
        ["bash", "-lc", extract_cmd],
        cwd=data_root,
    )
    extract_one = runner.run(
        f"{dataset.name}/tar-zstd-age-extract-one",
        ["bash", "-lc", extract_one_cmd],
        cwd=data_root,
    )
    return ResultRow(
        dataset=dataset.name,
        tool="tar+zstd+age",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=path_size(archive),
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def run_7z(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.7z"
    restore = restore_root / f"{dataset.name}-7z"
    seven_zip = seven_zip_executable()
    if seven_zip is None:
        raise RuntimeError("missing executable(s): 7z or 7zz")
    remove_path(archive)
    remove_path(restore)
    create = runner.run(
        f"{dataset.name}/7z-create",
        [
            seven_zip,
            "a",
            "-t7z",
            "-m0=lzma2",
            f"-p{BENCH_PASSWORD}",
            "-mhe=on",
            str(archive),
            dataset.name,
        ],
        cwd=data_root,
    )
    verify = runner.run(
        f"{dataset.name}/7z-verify",
        [seven_zip, "t", f"-p{BENCH_PASSWORD}", str(archive)],
        cwd=data_root,
    )
    extract_all = runner.run(
        f"{dataset.name}/7z-extract-all",
        [seven_zip, "x", "-y", f"-p{BENCH_PASSWORD}", f"-o{restore}", str(archive)],
        cwd=data_root,
    )
    extract_one = runner.run(
        f"{dataset.name}/7z-extract-one",
        [
            seven_zip,
            "x",
            "-so",
            f"-p{BENCH_PASSWORD}",
            str(archive),
            f"{dataset.name}/{dataset.selected_relative_path}",
        ],
        cwd=data_root,
        stdout_to_null=True,
    )
    return ResultRow(
        dataset=dataset.name,
        tool="7z",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=path_size(archive),
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def run_zip(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.zip"
    restore = restore_root / f"{dataset.name}-zip"
    remove_path(archive)
    remove_path(restore)
    create = runner.run(
        f"{dataset.name}/zip-create",
        ["zip", "-qr", "-P", BENCH_PASSWORD, str(archive), dataset.name],
        cwd=data_root,
    )
    verify = runner.run(
        f"{dataset.name}/zip-verify",
        ["unzip", "-t", "-P", BENCH_PASSWORD, str(archive)],
        cwd=data_root,
    )
    extract_all = runner.run(
        f"{dataset.name}/zip-extract-all",
        ["unzip", "-q", "-P", BENCH_PASSWORD, str(archive), "-d", str(restore)],
        cwd=data_root,
    )
    extract_one = runner.run(
        f"{dataset.name}/zip-extract-one",
        [
            "unzip",
            "-p",
            "-P",
            BENCH_PASSWORD,
            str(archive),
            f"{dataset.name}/{dataset.selected_relative_path}",
        ],
        cwd=data_root,
        stdout_to_null=True,
    )
    return ResultRow(
        dataset=dataset.name,
        tool="zip",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=path_size(archive),
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
        notes="zip -P is a familiar baseline, not a modern encryption recommendation",
    )


def run_tzap_missing_volume_recovery(
    runner: CommandRunner,
    tzap: Path,
    data_root: Path,
    output_root: Path,
    dataset: DatasetSpec,
) -> RecoveryRow:
    key = output_root / "bench.key"
    if not key.exists():
        runner.run("tzap-keygen", [str(tzap), "keygen", "--output", str(key)], cwd=REPO_ROOT)

    base = output_root / f"{dataset.name}-recovery.tzap"
    for existing in output_root.glob(f"{dataset.name}-recovery.vol*.tzap"):
        remove_path(existing)
    create = runner.run(
        f"{dataset.name}/tzap-recovery-create",
        [
            str(tzap),
            "create",
            "--keyfile",
            str(key),
            "--volumes",
            "3",
            "--volume-loss-tolerance",
            "1",
            "-o",
            str(base),
            dataset.name,
        ],
        cwd=data_root,
    )
    all_volume_size = volume_set_size(base)
    missing = output_root / f"{dataset.name}-recovery.vol001.tzap"
    hidden = output_root / f"{dataset.name}-recovery.vol001.tzap.missing"
    remove_path(hidden)
    missing.rename(hidden)
    try:
        recover = runner.run(
            f"{dataset.name}/tzap-recovery-verify-missing-volume",
            [
                str(tzap),
                "verify",
                "--keyfile",
                str(key),
                str(output_root / f"{dataset.name}-recovery.vol000.tzap"),
            ],
            cwd=data_root,
        )
    finally:
        hidden.rename(missing)

    return RecoveryRow(
        dataset=dataset.name,
        scenario="missing volume within tolerance",
        create_s=create.seconds,
        recover_verify_s=recover.seconds,
        output_size_bytes=all_volume_size,
    )


def corrupt_first_payload_block(volume: Path) -> bool:
    data = bytearray(volume.read_bytes())
    if len(data) < 128:
        return False
    crypto_header_length = int.from_bytes(data[52:56], "little")
    crypto_start = 128
    crypto_end = crypto_start + crypto_header_length
    if crypto_end + 76 > len(data):
        return False
    block_size = int.from_bytes(data[crypto_start + 24 : crypto_start + 28], "little")
    record_len = block_size + 20
    offset = crypto_end
    while offset + record_len <= len(data):
        if data[offset : offset + 4] != b"TZBK":
            break
        kind = data[offset + 12]
        if kind == 0:
            payload_start = offset + 16
            data[payload_start : payload_start + min(4096, block_size)] = b"\x00" * min(
                4096, block_size
            )
            volume.write_bytes(data)
            return True
        offset += record_len
    return False


def run_tzap_bitrot_recovery(
    runner: CommandRunner,
    tzap: Path,
    data_root: Path,
    output_root: Path,
    dataset: DatasetSpec,
) -> RecoveryRow:
    key = output_root / "bench.key"
    if not key.exists():
        runner.run("tzap-keygen", [str(tzap), "keygen", "--output", str(key)], cwd=REPO_ROOT)
    archive = output_root / f"{dataset.name}-bitrot.tzap"
    remove_path(archive)
    create = runner.run(
        f"{dataset.name}/tzap-bitrot-create",
        [
            str(tzap),
            "create",
            "--keyfile",
            str(key),
            "--bit-rot-buffer-pct",
            "5",
            "--block-size",
            "4K",
            "--chunk-size",
            "4K",
            "--envelope-size",
            "1M",
            "-o",
            str(archive),
            dataset.name,
        ],
        cwd=data_root,
    )
    if not corrupt_first_payload_block(archive):
        return RecoveryRow(
            dataset=dataset.name,
            scenario="damaged payload block within bit-rot budget",
            create_s=create.seconds,
            output_size_bytes=path_size(archive),
            status="skipped",
            notes="could not locate a payload block to corrupt",
        )
    recover = runner.run(
        f"{dataset.name}/tzap-bitrot-verify",
        [str(tzap), "verify", "--keyfile", str(key), str(archive)],
        cwd=data_root,
    )
    return RecoveryRow(
        dataset=dataset.name,
        scenario="damaged payload block within bit-rot budget",
        create_s=create.seconds,
        recover_verify_s=recover.seconds,
        output_size_bytes=path_size(archive),
    )


def available(tool: str) -> bool:
    return shutil.which(tool) is not None


def seven_zip_executable() -> str | None:
    return shutil.which("7z") or shutil.which("7zz")


def skip_row(dataset: DatasetSpec, tool: str, reason: str) -> ResultRow:
    return ResultRow(dataset=dataset.name, tool=tool, status="skipped", notes=reason)


def write_csv(path: Path, rows: list[ResultRow]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[field.name for field in dataclasses.fields(ResultRow)],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(dataclasses.asdict(row))


def write_recovery_csv(path: Path, rows: list[RecoveryRow]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[field.name for field in dataclasses.fields(RecoveryRow)],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(dataclasses.asdict(row))


def fmt_seconds(value: float | None) -> str:
    return "" if value is None else f"{value:.3f}"


def fmt_int(value: int | None) -> str:
    return "" if value is None else str(value)


def write_markdown(path: Path, rows: list[ResultRow], recovery_rows: list[RecoveryRow], meta: dict) -> None:
    lines = [
        "# tzap Benchmark Results",
        "",
        "Generated by `scripts/tzap_benchmark.py`.",
        "",
        "## Environment",
        "",
        f"- Timestamp: `{meta['timestamp']}`",
        f"- Host: `{meta['platform']}`",
        f"- Python: `{meta['python']}`",
        f"- tzap: `{meta['tzap']}`",
        f"- Profile: `{meta['profile']}`",
        "",
        "## Workflow Results",
        "",
        "| Dataset | Tool | Create (s) | Verify/Test (s) | Full Extract (s) | One File (s) | Output Bytes | Peak RSS KiB | Status | Notes |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    row.dataset,
                    row.tool,
                    fmt_seconds(row.create_s),
                    fmt_seconds(row.verify_s),
                    fmt_seconds(row.extract_all_s),
                    fmt_seconds(row.extract_one_s),
                    fmt_int(row.output_size_bytes),
                    fmt_int(row.peak_rss_kib),
                    row.status,
                    row.notes.replace("|", "\\|"),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## tzap Recovery Results",
            "",
            "| Dataset | Scenario | Create (s) | Recovery Verify (s) | Output Bytes | Status | Notes |",
            "| --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for row in recovery_rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    row.dataset,
                    row.scenario,
                    fmt_seconds(row.create_s),
                    fmt_seconds(row.recover_verify_s),
                    fmt_int(row.output_size_bytes),
                    row.status,
                    row.notes.replace("|", "\\|"),
                ]
            )
            + " |"
        )

    path.write_text("\n".join(lines) + "\n")


def parse_tools(value: str) -> list[str]:
    tools = [item.strip() for item in value.split(",") if item.strip()]
    valid = {"tzap", "tar-zstd", "tar-zstd-age", "7z", "zip"}
    unknown = sorted(set(tools) - valid)
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown tools: {', '.join(unknown)}")
    return tools


def tool_runner(tool: str) -> Callable[..., ResultRow]:
    return {
        "tzap": run_tzap,
        "tar-zstd": run_tar_zstd,
        "tar-zstd-age": run_tar_zstd_age,
        "7z": run_7z,
        "zip": run_zip,
    }[tool]


def missing_tool_reason(tool: str) -> str | None:
    requirements = {
        "tzap": [],
        "tar-zstd": ["tar", "zstd", "bash"],
        "tar-zstd-age": ["tar", "zstd", "age", "age-keygen", "bash"],
        "7z": [],
        "zip": ["zip", "unzip"],
    }[tool]
    missing = [name for name in requirements if not available(name)]
    if tool == "7z" and seven_zip_executable() is None:
        missing.append("7z or 7zz")
    return f"missing executable(s): {', '.join(missing)}" if missing else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["smoke", "standard"], default="smoke")
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--tzap", type=Path, default=None, help="path to an existing tzap binary")
    parser.add_argument("--skip-build", action="store_true", help="do not build target/release/tzap")
    parser.add_argument(
        "--tools",
        type=parse_tools,
        default=parse_tools("tzap,tar-zstd,tar-zstd-age,7z,zip"),
        help="comma-separated tools: tzap,tar-zstd,tar-zstd-age,7z,zip",
    )
    parser.add_argument(
        "--datasets",
        default="many-small,large-file,mixed-backup",
        help="comma-separated datasets to run",
    )
    args = parser.parse_args()

    work_dir: Path = args.work_dir
    data_root = work_dir / "data"
    output_root = work_dir / "archives"
    restore_root = work_dir / "restored"
    result_root = work_dir / "results"
    log_root = work_dir / "logs"
    for path in (output_root, restore_root, result_root, log_root):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    tzap = build_tzap(args.skip_build, args.tzap)
    runner = CommandRunner(log_root)
    datasets = create_datasets(data_root, args.profile)
    wanted_datasets = {item.strip() for item in args.datasets.split(",") if item.strip()}
    datasets = [dataset for dataset in datasets if dataset.name in wanted_datasets]
    if not datasets:
        raise SystemExit("no datasets selected")

    rows: list[ResultRow] = []
    recovery_rows: list[RecoveryRow] = []
    for dataset in datasets:
        for tool in args.tools:
            reason = missing_tool_reason(tool)
            if reason is not None:
                rows.append(skip_row(dataset, tool, reason))
                continue
            try:
                if tool == "tzap":
                    rows.append(
                        run_tzap(runner, tzap, data_root, output_root, restore_root, dataset)
                    )
                else:
                    rows.append(
                        tool_runner(tool)(runner, data_root, output_root, restore_root, dataset)
                    )
            except Exception as exc:  # keep the sheet useful when one baseline fails
                rows.append(
                    ResultRow(dataset=dataset.name, tool=tool, status="failed", notes=str(exc))
                )

        if "tzap" in args.tools:
            for recovery_fn in (run_tzap_missing_volume_recovery, run_tzap_bitrot_recovery):
                try:
                    recovery_rows.append(
                        recovery_fn(runner, tzap, data_root, output_root, dataset)
                    )
                except Exception as exc:
                    recovery_rows.append(
                        RecoveryRow(
                            dataset=dataset.name,
                            scenario=recovery_fn.__name__.replace("run_tzap_", "").replace("_", " "),
                            status="failed",
                            notes=str(exc),
                        )
                    )

    meta = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "profile": args.profile,
        "tzap": str(tzap),
        "tools": args.tools,
        "datasets": [dataset.name for dataset in datasets],
        "gnu_time": str(runner.gnu_time) if runner.gnu_time else None,
    }
    (result_root / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    write_csv(result_root / "results.csv", rows)
    write_recovery_csv(result_root / "recovery.csv", recovery_rows)
    write_markdown(result_root / "results.md", rows, recovery_rows, meta)

    print(f"wrote {result_root / 'results.csv'}")
    print(f"wrote {result_root / 'recovery.csv'}")
    print(f"wrote {result_root / 'results.md'}")
    if runner.gnu_time is None:
        print("peak RSS blank: GNU time was not found (install gtime on macOS)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
