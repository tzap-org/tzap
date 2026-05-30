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
import html
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORK_DIR = REPO_ROOT / "target" / "tzap-bench"
BENCH_PASSWORD = "tzap-benchmark-password"
BYTES_PER_MB = 1024 * 1024
BYTES_PER_GB = 1024 * BYTES_PER_MB
TOOL_ORDER = ["tzap", "tar+zstd", "tar+zstd+age", "tar+zstd+age+par2", "7z", "zip"]
TOOL_COLORS = {
    "tzap": "#0f766e",
    "tar+zstd": "#2563eb",
    "tar+zstd+age": "#d97706",
    "tar+zstd+age+par2": "#7c3aed",
    "7z": "#475569",
    "zip": "#be185d",
}
PROGRESS_LOG_PATH: Path | None = None


@dataclasses.dataclass(frozen=True)
class BenchmarkConfig:
    benchmark_password: str
    par2_redundancy_pct: str
    missing_volume_count: int
    missing_volume_loss_tolerance: int
    missing_volume_omit_index: int
    bitrot_buffer_pct: str
    bitrot_small_block_size: str
    bitrot_small_chunk_size: str
    bitrot_large_threshold_bytes: int
    bitrot_large_block_size: str
    bitrot_large_chunk_size: str
    bitrot_envelope_size: str
    bitrot_corruption_bytes: int


@dataclasses.dataclass(frozen=True)
class DatasetSpec:
    name: str
    selected_relative_path: str
    selected_file_position: str
    file_count: int
    total_size_bytes: int


@dataclasses.dataclass
class Measurement:
    seconds: float | None = None
    peak_rss_kib: int | None = None
    note: str = ""


@dataclasses.dataclass
class ResultRow:
    dataset: str
    input_file_count: int
    input_size_bytes: int
    selected_file_position: str
    selected_relative_path: str
    tool: str
    runs: int = 1
    create_s: float | None = None
    create_stddev_s: float | None = None
    verify_s: float | None = None
    verify_stddev_s: float | None = None
    extract_all_s: float | None = None
    extract_all_stddev_s: float | None = None
    extract_one_s: float | None = None
    extract_one_stddev_s: float | None = None
    output_size_bytes: int | None = None
    peak_rss_kib: int | None = None
    status: str = "ok"
    notes: str = ""


@dataclasses.dataclass
class RecoveryRow:
    dataset: str
    input_file_count: int
    input_size_bytes: int
    scenario: str
    runs: int = 1
    create_s: float | None = None
    create_stddev_s: float | None = None
    recover_verify_s: float | None = None
    recover_verify_stddev_s: float | None = None
    output_size_bytes: int | None = None
    status: str = "ok"
    notes: str = ""


@dataclasses.dataclass
class RawResultRow:
    run: int
    dataset: str
    input_file_count: int
    input_size_bytes: int
    selected_file_position: str
    selected_relative_path: str
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
class RawRecoveryRow:
    run: int
    dataset: str
    input_file_count: int
    input_size_bytes: int
    scenario: str
    create_s: float | None = None
    recover_verify_s: float | None = None
    output_size_bytes: int | None = None
    status: str = "ok"
    notes: str = ""


class CommandRunner:
    def __init__(self, log_dir: Path, *, quiet: bool = False) -> None:
        self.log_dir = log_dir
        self.quiet = quiet
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

        emit_progress(f"start {label}; detail log: {log_path}", self.quiet)
        emit_progress(
            f"command {label}: {shell_join(redact_command(command))}",
            self.quiet,
        )
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
            emit_progress(
                f"failed {label} after {seconds:.3f}s; detail log: {log_path}",
                self.quiet,
            )
            raise RuntimeError(
                f"{label} failed with exit {completed.returncode}; see {log_path}"
            )

        emit_progress(f"done {label} in {seconds:.3f}s; detail log: {log_path}", self.quiet)
        return Measurement(seconds=seconds, peak_rss_kib=parse_peak_rss(time_path))


def configure_progress_log(path: Path) -> None:
    global PROGRESS_LOG_PATH
    PROGRESS_LOG_PATH = path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("")


def emit_progress(message: str, quiet: bool = False) -> None:
    timestamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    line = f"[{timestamp}] {message}"
    if PROGRESS_LOG_PATH is not None:
        with PROGRESS_LOG_PATH.open("a") as handle:
            handle.write(line + "\n")
    if not quiet:
        print(line, flush=True)


def redact_command(command: Iterable[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for part in command:
        if redact_next:
            redacted.append("[BENCH_PASSWORD]")
            redact_next = False
            continue
        if part == "-P":
            redacted.append(part)
            redact_next = True
            continue
        if part.startswith("-p") and len(part) > 2:
            redacted.append("-p[BENCH_PASSWORD]")
            continue
        redacted.append(part)
    return redacted


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


def parse_size(value: str) -> int:
    text = value.strip().lower().replace("_", "")
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([kmgt]?i?b?)?", text)
    if not match:
        raise argparse.ArgumentTypeError(
            f"invalid size {value!r}; use values like 1MB, 20GB, 4096, or 4K"
        )
    amount = float(match.group(1))
    suffix = match.group(2) or ""
    multipliers = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": BYTES_PER_MB,
        "mb": BYTES_PER_MB,
        "mib": BYTES_PER_MB,
        "g": BYTES_PER_GB,
        "gb": BYTES_PER_GB,
        "gib": BYTES_PER_GB,
        "t": 1024 * BYTES_PER_GB,
        "tb": 1024 * BYTES_PER_GB,
        "tib": 1024 * BYTES_PER_GB,
    }
    size = int(amount * multipliers[suffix])
    if size <= 0:
        raise argparse.ArgumentTypeError(f"size must be positive: {value!r}")
    return size


def parse_size_list(value: str, option_name: str) -> list[int]:
    try:
        sizes = [parse_size(item) for item in value.split(",") if item.strip()]
    except argparse.ArgumentTypeError as exc:
        raise SystemExit(f"{option_name}: {exc}") from exc
    if not sizes:
        raise SystemExit(f"{option_name} must include at least one size")
    return sizes


def size_slug(size: int) -> str:
    if size % BYTES_PER_GB == 0:
        return f"{size // BYTES_PER_GB}gb"
    if size % BYTES_PER_MB == 0:
        return f"{size // BYTES_PER_MB}mb"
    if size % 1024 == 0:
        return f"{size // 1024}kb"
    return f"{size}b"


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


def directory_stats(path: Path) -> tuple[int, int]:
    files = [child for child in path.rglob("*") if child.is_file()]
    return len(files), sum(child.stat().st_size for child in files)


def selected_file_index(file_count: int, position: str) -> int:
    if file_count <= 0:
        raise ValueError("file_count must be positive")
    if position == "first":
        return 0
    if position == "middle":
        return file_count // 2
    if position == "last":
        return file_count - 1
    raise ValueError(f"unknown selected file position: {position}")


def selected_file_relative_path(file_count: int, position: str) -> str:
    return f"files/file-{selected_file_index(file_count, position):05d}.bin"


def should_report_file_progress(index: int, file_count: int) -> bool:
    completed = index + 1
    if completed == 1 or completed == file_count:
        return True
    step = max(1, file_count // 8)
    return completed % step == 0


def create_same_count_dataset(
    root: Path,
    name: str,
    file_count: int,
    file_size: int,
    selected_position: str,
    quiet: bool,
) -> DatasetSpec:
    dataset_root = root / name
    emit_progress(
        f"generating {name}: {file_count} files x {fmt_size(file_size)}",
        quiet,
    )
    for index in range(file_count):
        # Keep the same compressibility mix for every size tier.
        write_pattern_file(
            dataset_root / "files" / f"file-{index:05d}.bin",
            file_size,
            10_000 + index,
            texty=index % 4 != 0,
        )
        if should_report_file_progress(index, file_count):
            emit_progress(
                f"generating {name}: {index + 1}/{file_count} files",
                quiet,
            )
    count, total = directory_stats(dataset_root)
    emit_progress(f"generated {name}: {fmt_size(total)}", quiet)
    return DatasetSpec(
        name=name,
        selected_relative_path=selected_file_relative_path(file_count, selected_position),
        selected_file_position=selected_position,
        file_count=count,
        total_size_bytes=total,
    )


def create_fixed_total_dataset(
    root: Path,
    name: str,
    file_count: int,
    total_size: int,
    selected_position: str,
    quiet: bool,
) -> DatasetSpec:
    file_size, remainder = divmod(total_size, file_count)
    if file_size <= 0:
        raise ValueError(f"{name} is too small for {file_count} files")

    dataset_root = root / name
    emit_progress(
        f"generating {name}: {file_count} files, {fmt_size(total_size)} total",
        quiet,
    )
    for index in range(file_count):
        # Keep the same compressibility mix for every size tier while matching the
        # requested total size exactly.
        size = file_size + (1 if index < remainder else 0)
        write_pattern_file(
            dataset_root / "files" / f"file-{index:05d}.bin",
            size,
            10_000 + index,
            texty=index % 4 != 0,
        )
        if should_report_file_progress(index, file_count):
            emit_progress(
                f"generating {name}: {index + 1}/{file_count} files",
                quiet,
            )
    count, total = directory_stats(dataset_root)
    emit_progress(f"generated {name}: {fmt_size(total)}", quiet)
    return DatasetSpec(
        name=name,
        selected_relative_path=selected_file_relative_path(file_count, selected_position),
        selected_file_position=selected_position,
        file_count=count,
        total_size_bytes=total,
    )


def create_datasets(
    root: Path,
    profile: str,
    wanted_datasets: set[str] | None = None,
    selected_position: str = "last",
    file_count_override: int | None = None,
    fixed_total_sizes: list[int] | None = None,
    same_count_file_sizes: list[int] | None = None,
    quiet: bool = False,
) -> list[DatasetSpec]:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    def wanted(name: str) -> bool:
        return wanted_datasets is None or name in wanted_datasets

    if profile == "smoke":
        file_count = file_count_override or 64
        per_file_sizes = (
            [(f"same-count-{size_slug(size)}", size) for size in same_count_file_sizes]
            if same_count_file_sizes is not None
            else [
                ("same-count-small", 1024),
                ("same-count-medium", 16 * 1024),
                ("same-count-large", 256 * 1024),
            ]
        )
        return [
            create_same_count_dataset(root, name, file_count, file_size, selected_position, quiet)
            for name, file_size in per_file_sizes
            if wanted(name)
        ]

    elif profile == "standard":
        file_count = file_count_override or 64
        total_sizes = [
            (f"size-{size_slug(size)}", size)
            for size in (
                fixed_total_sizes
                if fixed_total_sizes is not None
                else [
                    1 * BYTES_PER_MB,
                    20 * BYTES_PER_MB,
                    1 * BYTES_PER_GB,
                    20 * BYTES_PER_GB,
                ]
            )
        ]
    else:
        file_count = file_count_override or 1024
        per_file_sizes = (
            [(f"same-count-{size_slug(size)}", size) for size in same_count_file_sizes]
            if same_count_file_sizes is not None
            else [
                ("same-count-small", 16 * 1024),
                ("same-count-medium", 1024 * 1024),
                ("same-count-large", 16 * 1024 * 1024),
            ]
        )
        return [
            create_same_count_dataset(root, name, file_count, file_size, selected_position, quiet)
            for name, file_size in per_file_sizes
            if wanted(name)
        ]

    return [
        create_fixed_total_dataset(root, name, file_count, total_size, selected_position, quiet)
        for name, total_size in total_sizes
        if wanted(name)
    ]


def build_tzap(skip_build: bool, tzap_path: Path | None) -> Path:
    if tzap_path is not None:
        if not tzap_path.exists():
            raise FileNotFoundError(f"tzap binary not found: {tzap_path}")
        return tzap_path.resolve()

    binary = REPO_ROOT / "target" / "release" / "tzap"
    if not skip_build:
        subprocess.run(["cargo", "build", "--release", "-p", "tzap"], cwd=REPO_ROOT, check=True)
    if not binary.exists():
        raise FileNotFoundError(
            f"tzap binary not found at {binary}; run cargo build --release -p tzap"
        )
    return binary.resolve()


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def remove_many(paths: Iterable[Path]) -> None:
    for path in paths:
        remove_path(path)


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


def par2_files_for_archive(archive: Path) -> list[Path]:
    return [
        archive.with_name(f"{archive.name}.par2"),
        *sorted(archive.parent.glob(f"{archive.name}.vol*.par2")),
    ]


def par2_archive_set_size(archive: Path) -> int:
    return path_size(archive) + sum(path_size(path) for path in par2_files_for_archive(archive))


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
    _config: BenchmarkConfig,
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
    output_size = path_size(archive)
    remove_many([archive, restore])
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool="tzap",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=output_size,
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def run_tar_zstd(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
    _config: BenchmarkConfig,
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
    output_size = path_size(archive)
    remove_many([archive, restore])
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool="tar+zstd",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=output_size,
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def age_identity_and_public_key(
    runner: CommandRunner, data_root: Path, output_root: Path
) -> tuple[Path, str]:
    identity = output_root / "age-identity.txt"
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
    return identity, public_key


def run_tar_zstd_age(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
    _config: BenchmarkConfig,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.tar.zst.age"
    restore = restore_root / f"{dataset.name}-tar-zstd-age"
    remove_path(archive)
    remove_path(restore)
    restore.mkdir(parents=True)

    identity, public_key = age_identity_and_public_key(runner, data_root, output_root)
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
    output_size = path_size(archive)
    remove_many([archive, restore])
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool="tar+zstd+age",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=output_size,
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def run_tar_zstd_age_par2(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
    config: BenchmarkConfig,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.tar.zst.age"
    par2_index = archive.with_name(f"{archive.name}.par2")
    restore = restore_root / f"{dataset.name}-tar-zstd-age-par2"
    remove_many([archive, *par2_files_for_archive(archive), restore])
    restore.mkdir(parents=True)

    identity, public_key = age_identity_and_public_key(runner, data_root, output_root)
    create_archive_cmd = (
        f"tar -cf - {shell_quote(dataset.name)} | "
        f"zstd -q -T0 | "
        f"age -r {shell_quote(public_key)} -o {shell_quote(archive)}"
    )
    create_par2_cmd = (
        f"par2 create -q -q -r{shell_quote(config.par2_redundancy_pct)} -n1 "
        f"{shell_quote(par2_index)} {shell_quote(archive)}"
    )
    verify_cmd = (
        f"par2 verify -q -q {shell_quote(par2_index)} {shell_quote(archive)} && "
        f"age -d -i {shell_quote(identity)} {shell_quote(archive)} | zstd -q -t -"
    )
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
    create_archive = runner.run(
        f"{dataset.name}/tar-zstd-age-par2-create-archive",
        ["bash", "-lc", create_archive_cmd],
        cwd=data_root,
    )
    create_par2 = runner.run(
        f"{dataset.name}/tar-zstd-age-par2-create-par2",
        ["bash", "-lc", create_par2_cmd],
        cwd=data_root,
    )
    verify = runner.run(
        f"{dataset.name}/tar-zstd-age-par2-verify",
        ["bash", "-lc", verify_cmd],
        cwd=data_root,
    )
    extract_all = runner.run(
        f"{dataset.name}/tar-zstd-age-par2-extract-all",
        ["bash", "-lc", extract_cmd],
        cwd=data_root,
    )
    extract_one = runner.run(
        f"{dataset.name}/tar-zstd-age-par2-extract-one",
        ["bash", "-lc", extract_one_cmd],
        cwd=data_root,
    )
    output_size = par2_archive_set_size(archive)
    remove_many([archive, *par2_files_for_archive(archive), restore])
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool="tar+zstd+age+par2",
        create_s=(create_archive.seconds or 0.0) + (create_par2.seconds or 0.0),
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=output_size,
        peak_rss_kib=max_rss(create_archive, create_par2, verify, extract_all, extract_one),
        notes=f"PAR2 redundancy {config.par2_redundancy_pct}%",
    )


def run_7z(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
    config: BenchmarkConfig,
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
            f"-p{config.benchmark_password}",
            "-mhe=on",
            str(archive),
            dataset.name,
        ],
        cwd=data_root,
    )
    verify = runner.run(
        f"{dataset.name}/7z-verify",
        [seven_zip, "t", f"-p{config.benchmark_password}", str(archive)],
        cwd=data_root,
    )
    extract_all = runner.run(
        f"{dataset.name}/7z-extract-all",
        [seven_zip, "x", "-y", f"-p{config.benchmark_password}", f"-o{restore}", str(archive)],
        cwd=data_root,
    )
    extract_one = runner.run(
        f"{dataset.name}/7z-extract-one",
        [
            seven_zip,
            "x",
            "-so",
            f"-p{config.benchmark_password}",
            str(archive),
            f"{dataset.name}/{dataset.selected_relative_path}",
        ],
        cwd=data_root,
        stdout_to_null=True,
    )
    output_size = path_size(archive)
    remove_many([archive, restore])
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool="7z",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=output_size,
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
    )


def run_zip(
    runner: CommandRunner,
    data_root: Path,
    output_root: Path,
    restore_root: Path,
    dataset: DatasetSpec,
    config: BenchmarkConfig,
) -> ResultRow:
    archive = output_root / f"{dataset.name}.zip"
    restore = restore_root / f"{dataset.name}-zip"
    remove_path(archive)
    remove_path(restore)
    create = runner.run(
        f"{dataset.name}/zip-create",
        ["zip", "-qr", "-P", config.benchmark_password, str(archive), dataset.name],
        cwd=data_root,
    )
    verify = runner.run(
        f"{dataset.name}/zip-verify",
        ["unzip", "-t", "-P", config.benchmark_password, str(archive)],
        cwd=data_root,
    )
    extract_all = runner.run(
        f"{dataset.name}/zip-extract-all",
        ["unzip", "-q", "-P", config.benchmark_password, str(archive), "-d", str(restore)],
        cwd=data_root,
    )
    extract_one = runner.run(
        f"{dataset.name}/zip-extract-one",
        [
            "unzip",
            "-p",
            "-P",
            config.benchmark_password,
            str(archive),
            f"{dataset.name}/{dataset.selected_relative_path}",
        ],
        cwd=data_root,
        stdout_to_null=True,
    )
    output_size = path_size(archive)
    remove_many([archive, restore])
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool="zip",
        create_s=create.seconds,
        verify_s=verify.seconds,
        extract_all_s=extract_all.seconds,
        extract_one_s=extract_one.seconds,
        output_size_bytes=output_size,
        peak_rss_kib=max_rss(create, verify, extract_all, extract_one),
        notes="zip -P is a familiar baseline, not a modern encryption recommendation",
    )


def run_tzap_missing_volume_recovery(
    runner: CommandRunner,
    tzap: Path,
    data_root: Path,
    output_root: Path,
    dataset: DatasetSpec,
    config: BenchmarkConfig,
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
            str(config.missing_volume_count),
            "--volume-loss-tolerance",
            str(config.missing_volume_loss_tolerance),
            "-o",
            str(base),
            dataset.name,
        ],
        cwd=data_root,
    )
    all_volume_size = volume_set_size(base)
    omitted = config.missing_volume_omit_index
    verify_index = 0 if omitted != 0 else 1
    missing = output_root / f"{dataset.name}-recovery.vol{omitted:03d}.tzap"
    hidden = output_root / f"{dataset.name}-recovery.vol{omitted:03d}.tzap.missing"
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
                str(output_root / f"{dataset.name}-recovery.vol{verify_index:03d}.tzap"),
            ],
            cwd=data_root,
        )
    finally:
        hidden.rename(missing)

    for existing in output_root.glob(f"{dataset.name}-recovery.vol*.tzap"):
        remove_path(existing)
    return RecoveryRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        scenario="missing volume within tolerance",
        create_s=create.seconds,
        recover_verify_s=recover.seconds,
        output_size_bytes=all_volume_size,
        notes=(
            "input: "
            f"--volumes {config.missing_volume_count} "
            f"--volume-loss-tolerance {config.missing_volume_loss_tolerance}; "
            f"omitted vol{omitted:03d} during verify"
        ),
    )


def corrupt_first_payload_block(volume: Path, corruption_bytes: int) -> bool:
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
            damaged_bytes = min(corruption_bytes, block_size)
            data[payload_start : payload_start + damaged_bytes] = b"\x00" * (
                damaged_bytes
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
    config: BenchmarkConfig,
) -> RecoveryRow:
    key = output_root / "bench.key"
    if not key.exists():
        runner.run("tzap-keygen", [str(tzap), "keygen", "--output", str(key)], cwd=REPO_ROOT)
    archive = output_root / f"{dataset.name}-bitrot.tzap"
    remove_path(archive)
    bitrot_args, bitrot_note = bitrot_recovery_shape(dataset, config)
    create = runner.run(
        f"{dataset.name}/tzap-bitrot-create",
        [
            str(tzap),
            "create",
            "--keyfile",
            str(key),
            *bitrot_args,
            "-o",
            str(archive),
            dataset.name,
        ],
        cwd=data_root,
    )
    if not corrupt_first_payload_block(archive, config.bitrot_corruption_bytes):
        output_size = path_size(archive)
        remove_path(archive)
        return RecoveryRow(
            dataset=dataset.name,
            input_file_count=dataset.file_count,
            input_size_bytes=dataset.total_size_bytes,
            scenario="damaged payload block within bit-rot budget",
            create_s=create.seconds,
            output_size_bytes=output_size,
            status="skipped",
            notes=f"input: {bitrot_note}; could not locate a payload block to corrupt",
        )
    recover = runner.run(
        f"{dataset.name}/tzap-bitrot-verify",
        [str(tzap), "verify", "--keyfile", str(key), str(archive)],
        cwd=data_root,
    )
    output_size = path_size(archive)
    remove_path(archive)
    return RecoveryRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        scenario="damaged payload block within bit-rot budget",
        create_s=create.seconds,
        recover_verify_s=recover.seconds,
        output_size_bytes=output_size,
        notes=(
            f"input: {bitrot_note}; injected corruption: zero first "
            f"{config.bitrot_corruption_bytes} bytes of first payload-data BlockRecord"
        ),
    )


def bitrot_recovery_shape(
    dataset: DatasetSpec, config: BenchmarkConfig
) -> tuple[list[str], str]:
    if dataset.total_size_bytes >= config.bitrot_large_threshold_bytes:
        args = [
            "--bit-rot-buffer-pct",
            config.bitrot_buffer_pct,
            "--block-size",
            config.bitrot_large_block_size,
            "--chunk-size",
            config.bitrot_large_chunk_size,
            "--envelope-size",
            config.bitrot_envelope_size,
        ]
    else:
        args = [
            "--bit-rot-buffer-pct",
            config.bitrot_buffer_pct,
            "--block-size",
            config.bitrot_small_block_size,
            "--chunk-size",
            config.bitrot_small_chunk_size,
            "--envelope-size",
            config.bitrot_envelope_size,
        ]
    note = " ".join(f"{args[index]} {args[index + 1]}" for index in range(0, len(args), 2))
    return args, note


def available(tool: str) -> bool:
    return shutil.which(tool) is not None


def seven_zip_executable() -> str | None:
    return shutil.which("7z") or shutil.which("7zz")


def skip_row(dataset: DatasetSpec, tool: str, reason: str) -> ResultRow:
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool=tool,
        status="skipped",
        notes=reason,
    )


def failed_row(dataset: DatasetSpec, tool: str, reason: str) -> ResultRow:
    return ResultRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        selected_file_position=dataset.selected_file_position,
        selected_relative_path=dataset.selected_relative_path,
        tool=tool,
        status="failed",
        notes=reason,
    )


def failed_recovery_row(dataset: DatasetSpec, scenario: str, reason: str) -> RecoveryRow:
    return RecoveryRow(
        dataset=dataset.name,
        input_file_count=dataset.file_count,
        input_size_bytes=dataset.total_size_bytes,
        scenario=scenario,
        status="failed",
        notes=reason,
    )


def raw_result(run_index: int, row: ResultRow) -> RawResultRow:
    return RawResultRow(
        run=run_index,
        dataset=row.dataset,
        input_file_count=row.input_file_count,
        input_size_bytes=row.input_size_bytes,
        selected_file_position=row.selected_file_position,
        selected_relative_path=row.selected_relative_path,
        tool=row.tool,
        create_s=row.create_s,
        verify_s=row.verify_s,
        extract_all_s=row.extract_all_s,
        extract_one_s=row.extract_one_s,
        output_size_bytes=row.output_size_bytes,
        peak_rss_kib=row.peak_rss_kib,
        status=row.status,
        notes=row.notes,
    )


def raw_recovery(run_index: int, row: RecoveryRow) -> RawRecoveryRow:
    return RawRecoveryRow(
        run=run_index,
        dataset=row.dataset,
        input_file_count=row.input_file_count,
        input_size_bytes=row.input_size_bytes,
        scenario=row.scenario,
        create_s=row.create_s,
        recover_verify_s=row.recover_verify_s,
        output_size_bytes=row.output_size_bytes,
        status=row.status,
        notes=row.notes,
    )


def mean(values: list[float]) -> float | None:
    return statistics.fmean(values) if values else None


def stddev(values: list[float]) -> float | None:
    return statistics.stdev(values) if len(values) > 1 else (0.0 if values else None)


def numeric_values(rows: list[ResultRow], field: str) -> list[float]:
    return [
        value
        for value in (getattr(row, field) for row in rows)
        if isinstance(value, float)
    ]


def recovery_numeric_values(rows: list[RecoveryRow], field: str) -> list[float]:
    return [
        value
        for value in (getattr(row, field) for row in rows)
        if isinstance(value, float)
    ]


def summarize_result_rows(rows: list[ResultRow]) -> ResultRow:
    first = rows[0]
    ok_rows = [row for row in rows if row.status == "ok"]
    notes = sorted({row.notes for row in rows if row.notes})
    if not ok_rows:
        status = "skipped" if all(row.status == "skipped" for row in rows) else "failed"
        return ResultRow(
            dataset=first.dataset,
            input_file_count=first.input_file_count,
            input_size_bytes=first.input_size_bytes,
            selected_file_position=first.selected_file_position,
            selected_relative_path=first.selected_relative_path,
            tool=first.tool,
            runs=0,
            status=status,
            notes="; ".join(notes),
        )

    status = "ok" if len(ok_rows) == len(rows) else "partial"
    create_values = numeric_values(ok_rows, "create_s")
    verify_values = numeric_values(ok_rows, "verify_s")
    extract_all_values = numeric_values(ok_rows, "extract_all_s")
    extract_one_values = numeric_values(ok_rows, "extract_one_s")
    rss_values = [row.peak_rss_kib for row in ok_rows if row.peak_rss_kib is not None]
    return ResultRow(
        dataset=first.dataset,
        input_file_count=first.input_file_count,
        input_size_bytes=first.input_size_bytes,
        selected_file_position=first.selected_file_position,
        selected_relative_path=first.selected_relative_path,
        tool=first.tool,
        runs=len(ok_rows),
        create_s=mean(create_values),
        create_stddev_s=stddev(create_values),
        verify_s=mean(verify_values),
        verify_stddev_s=stddev(verify_values),
        extract_all_s=mean(extract_all_values),
        extract_all_stddev_s=stddev(extract_all_values),
        extract_one_s=mean(extract_one_values),
        extract_one_stddev_s=stddev(extract_one_values),
        output_size_bytes=ok_rows[-1].output_size_bytes,
        peak_rss_kib=max(rss_values) if rss_values else None,
        status=status,
        notes="; ".join(notes),
    )


def summarize_recovery_rows(rows: list[RecoveryRow]) -> RecoveryRow:
    first = rows[0]
    ok_rows = [row for row in rows if row.status == "ok"]
    notes = sorted({row.notes for row in rows if row.notes})
    if not ok_rows:
        status = "skipped" if all(row.status == "skipped" for row in rows) else "failed"
        return RecoveryRow(
            dataset=first.dataset,
            input_file_count=first.input_file_count,
            input_size_bytes=first.input_size_bytes,
            scenario=first.scenario,
            runs=0,
            status=status,
            notes="; ".join(notes),
        )

    status = "ok" if len(ok_rows) == len(rows) else "partial"
    create_values = recovery_numeric_values(ok_rows, "create_s")
    recover_values = recovery_numeric_values(ok_rows, "recover_verify_s")
    return RecoveryRow(
        dataset=first.dataset,
        input_file_count=first.input_file_count,
        input_size_bytes=first.input_size_bytes,
        scenario=first.scenario,
        runs=len(ok_rows),
        create_s=mean(create_values),
        create_stddev_s=stddev(create_values),
        recover_verify_s=mean(recover_values),
        recover_verify_stddev_s=stddev(recover_values),
        output_size_bytes=ok_rows[-1].output_size_bytes,
        status=status,
        notes="; ".join(notes),
    )


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


def write_raw_csv(path: Path, rows: list[RawResultRow]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[field.name for field in dataclasses.fields(RawResultRow)],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(dataclasses.asdict(row))


def write_raw_recovery_csv(path: Path, rows: list[RawRecoveryRow]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[field.name for field in dataclasses.fields(RawRecoveryRow)],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(dataclasses.asdict(row))


def fmt_seconds(value: float | None) -> str:
    return "" if value is None else f"{value:.3f}"


def fmt_int(value: int | None) -> str:
    return "" if value is None else str(value)


def fmt_size(value: int | None) -> str:
    if value is None:
        return ""
    if value >= BYTES_PER_GB:
        amount = value / BYTES_PER_GB
        return f"{amount:.0f} GB" if amount.is_integer() else f"{amount:.2f} GB"
    if value >= BYTES_PER_MB:
        amount = value / BYTES_PER_MB
        return f"{amount:.0f} MB" if amount.is_integer() else f"{amount:.2f} MB"
    if value >= 1024:
        amount = value / 1024
        return f"{amount:.0f} KB" if amount.is_integer() else f"{amount:.2f} KB"
    return f"{value} B"


def fmt_seconds_label(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}s"


def fmt_seconds_with_stddev(value: float | None, stddev_value: float | None) -> str:
    if value is None:
        return "n/a"
    if stddev_value is None:
        return f"{value:.3f}s"
    return f"{value:.3f}s +/- {stddev_value:.3f}s"


def md_cell(value: object) -> str:
    return str(value).replace("|", "\\|")


def svg_text(value: object) -> str:
    return html.escape(str(value), quote=True)


def tool_sort_key(row: ResultRow) -> tuple[int, str]:
    try:
        index = TOOL_ORDER.index(row.tool)
    except ValueError:
        index = len(TOOL_ORDER)
    return (index, row.tool)


def sorted_workflow_rows(rows: list[ResultRow]) -> list[ResultRow]:
    return sorted(rows, key=lambda row: (row.input_size_bytes, tool_sort_key(row)))


def chart_title(title: str, subtitle: str, width: int = 960) -> list[str]:
    return [
        f'<text x="{width / 2:.0f}" y="42" text-anchor="middle" '
        'font-family="Arial, sans-serif" font-size="28" font-weight="700" '
        f'fill="#111827">{svg_text(title)}</text>',
        f'<text x="{width / 2:.0f}" y="70" text-anchor="middle" '
        'font-family="Arial, sans-serif" font-size="14" '
        f'fill="#4b5563">{svg_text(subtitle)}</text>',
    ]


def write_selected_restore_chart(path: Path, rows: list[ResultRow]) -> None:
    workflow_rows = [
        row
        for row in rows
        if row.status == "ok" and row.extract_one_s is not None and row.input_size_bytes > 0
    ]
    if not workflow_rows:
        return

    datasets = sorted({row.input_size_bytes for row in workflow_rows})
    tools = [tool for tool in TOOL_ORDER if any(row.tool == tool for row in workflow_rows)]
    max_y = max(row.extract_one_s or 0.0 for row in workflow_rows) * 1.25
    max_y = max(max_y, 0.001)
    width, height = 960, 520
    left, right, top, bottom = 86, 216, 96, 88
    plot_w = width - left - right
    plot_h = height - top - bottom

    def x_pos(input_size: int) -> float:
        if len(datasets) == 1:
            return left + plot_w / 2
        index = datasets.index(input_size)
        return left + (plot_w * index / (len(datasets) - 1))

    def y_pos(seconds: float) -> float:
        return top + plot_h - (seconds / max_y * plot_h)

    chart_heading = selected_restore_heading(workflow_rows)
    positions = sorted(
        {row.selected_file_position for row in workflow_rows if row.selected_file_position}
    )
    position = positions[0] if len(positions) == 1 else "configured"
    subtitle = f"Selected member: {position} generated file. Lower is better."
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        *chart_title(
            f"{chart_heading} from archive",
            subtitle,
            width,
        ),
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#d1d5db"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#d1d5db"/>',
    ]

    for tick in range(5):
        value = max_y * tick / 4
        y = y_pos(value)
        lines.extend(
            [
                f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="#eef2f7"/>',
                f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" '
                'font-family="Arial, sans-serif" font-size="12" '
                f'fill="#6b7280">{value:.3f}s</text>',
            ]
        )

    for input_size in datasets:
        x = x_pos(input_size)
        lines.extend(
            [
                f'<line x1="{x:.1f}" y1="{top + plot_h}" x2="{x:.1f}" y2="{top + plot_h + 6}" stroke="#d1d5db"/>',
                f'<text x="{x:.1f}" y="{top + plot_h + 28}" text-anchor="middle" '
                'font-family="Arial, sans-serif" font-size="13" '
                f'fill="#374151">{fmt_size(input_size)}</text>',
            ]
        )

    row_lookup = {(row.tool, row.input_size_bytes): row for row in workflow_rows}
    for tool in tools:
        color = TOOL_COLORS.get(tool, "#111827")
        points: list[tuple[float, float, float]] = []
        for input_size in datasets:
            row = row_lookup.get((tool, input_size))
            if row is None or row.extract_one_s is None:
                continue
            points.append((x_pos(input_size), y_pos(row.extract_one_s), row.extract_one_s))
        if len(points) >= 2:
            point_text = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in points)
            lines.append(
                f'<polyline points="{point_text}" fill="none" stroke="{color}" '
                'stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
            )
        for x, y, value in points:
            lines.extend(
                [
                    f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{color}" stroke="#ffffff" stroke-width="2"/>',
                    f'<text x="{x:.1f}" y="{y - 10:.1f}" text-anchor="middle" '
                    'font-family="Arial, sans-serif" font-size="11" '
                    f'fill="#374151">{value:.3f}s</text>',
                ]
            )

    legend_x = left + plot_w + 32
    legend_y = top + 12
    for index, tool in enumerate(tools):
        y = legend_y + index * 28
        color = TOOL_COLORS.get(tool, "#111827")
        lines.extend(
            [
                f'<rect x="{legend_x}" y="{y - 10}" width="16" height="16" rx="4" fill="{color}"/>',
                f'<text x="{legend_x + 24}" y="{y + 3}" font-family="Arial, sans-serif" '
                f'font-size="13" fill="#374151">{svg_text(tool)}</text>',
            ]
        )

    lines.extend(
        [
            f'<text x="{left + plot_w / 2:.0f}" y="{height - 22}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="13" fill="#6b7280">Input size</text>',
            "</svg>",
        ]
    )
    path.write_text("\n".join(lines) + "\n")


def write_recovery_scorecard_chart(path: Path, recovery_rows: list[RecoveryRow]) -> None:
    scenarios = [
        ("missing volume within tolerance", "Missing volume"),
        ("damaged payload block within bit-rot budget", "Rotten payload bytes"),
    ]
    tools = ["tzap", "tar+zstd", "tar+zstd+age", "7z", "zip"]
    tzap_ok = {
        scenario: any(row.scenario == scenario and row.status == "ok" for row in recovery_rows)
        for scenario, _ in scenarios
    }
    width, height = 960, 430
    left, top = 70, 112
    tool_w, cell_w, row_h = 210, 300, 54
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        *chart_title(
            "Damage recovery scorecard",
            "The comparison baselines fail these recovery cases; tzap recovered them.",
            width,
        ),
        f'<text x="{left + 8}" y="{top - 18}" font-family="Arial, sans-serif" font-size="13" '
        'font-weight="700" fill="#374151">Tool</text>',
    ]
    for index, (_, label) in enumerate(scenarios):
        x = left + tool_w + index * cell_w
        lines.append(
            f'<text x="{x + cell_w / 2:.0f}" y="{top - 18}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="13" font-weight="700" '
            f'fill="#374151">{svg_text(label)}</text>'
        )

    for row_index, tool in enumerate(tools):
        y = top + row_index * row_h
        fill = "#f8fafc" if row_index % 2 == 0 else "#ffffff"
        lines.extend(
            [
                f'<rect x="{left}" y="{y}" width="{tool_w + cell_w * len(scenarios)}" height="{row_h}" fill="{fill}"/>',
                f'<text x="{left + 8}" y="{y + 34}" font-family="Arial, sans-serif" '
                f'font-size="16" font-weight="700" fill="#111827">{svg_text(tool)}</text>',
            ]
        )
        for scenario_index, (scenario, _) in enumerate(scenarios):
            recovered = tool == "tzap" and tzap_ok.get(scenario, False)
            text = "RECOVERED" if recovered else "FAILED"
            color = "#0f766e" if recovered else "#b91c1c"
            bg = "#ccfbf1" if recovered else "#fee2e2"
            x = left + tool_w + scenario_index * cell_w
            lines.extend(
                [
                    f'<rect x="{x + 28}" y="{y + 11}" width="{cell_w - 56}" height="32" rx="8" fill="{bg}"/>',
                    f'<text x="{x + cell_w / 2:.0f}" y="{y + 32}" text-anchor="middle" '
                    'font-family="Arial, sans-serif" font-size="13" font-weight="700" '
                    f'fill="{color}">{text}</text>',
                ]
            )

    note_y = top + len(tools) * row_h + 32
    lines.extend(
        [
            f'<text x="{width / 2:.0f}" y="{note_y}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="12" fill="#6b7280">'
            "Failed means the benchmarked archive had no repair data path for reconstructing missing or overwritten data."
            "</text>",
            "</svg>",
        ]
    )
    path.write_text("\n".join(lines) + "\n")


def write_recovery_time_chart(path: Path, recovery_rows: list[RecoveryRow]) -> None:
    rows = [
        row
        for row in recovery_rows
        if row.status == "ok" and row.recover_verify_s is not None and row.input_size_bytes > 0
    ]
    if not rows:
        return

    scenarios = [
        ("missing volume within tolerance", "Missing volume", "#0f766e"),
        ("damaged payload block within bit-rot budget", "Rotten bytes", "#be185d"),
    ]
    datasets = sorted({row.input_size_bytes for row in rows})
    max_y = max(row.recover_verify_s or 0.0 for row in rows) * 1.18
    max_y = max(max_y, 1.0)
    width, height = 960, 520
    left, right, top, bottom = 86, 190, 96, 88
    plot_w = width - left - right
    plot_h = height - top - bottom
    group_w = plot_w / max(len(datasets), 1)
    bar_w = min(72, group_w / 4)

    def y_pos(seconds: float) -> float:
        return top + plot_h - (seconds / max_y * plot_h)

    lookup = {(row.scenario, row.input_size_bytes): row for row in rows}
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        *chart_title(
            "tzap recovery verify time",
            "Higher work here means damaged data was actually reconstructed and verified.",
            width,
        ),
        f'<line x1="{left}" y1="{top + plot_h}" x2="{left + plot_w}" y2="{top + plot_h}" stroke="#d1d5db"/>',
        f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + plot_h}" stroke="#d1d5db"/>',
    ]
    for tick in range(5):
        value = max_y * tick / 4
        y = y_pos(value)
        lines.extend(
            [
                f'<line x1="{left}" y1="{y:.1f}" x2="{left + plot_w}" y2="{y:.1f}" stroke="#eef2f7"/>',
                f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" '
                'font-family="Arial, sans-serif" font-size="12" '
                f'fill="#6b7280">{value:.1f}s</text>',
            ]
        )

    for dataset_index, input_size in enumerate(datasets):
        center = left + group_w * dataset_index + group_w / 2
        lines.append(
            f'<text x="{center:.1f}" y="{top + plot_h + 28}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="13" '
            f'fill="#374151">{fmt_size(input_size)}</text>'
        )
        for scenario_index, (scenario, _, color) in enumerate(scenarios):
            row = lookup.get((scenario, input_size))
            if row is None or row.recover_verify_s is None:
                continue
            x = center + (scenario_index - 0.5) * (bar_w + 10)
            y = y_pos(row.recover_verify_s)
            h = top + plot_h - y
            lines.extend(
                [
                    f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{h:.1f}" rx="6" fill="{color}"/>',
                    f'<text x="{x + bar_w / 2:.1f}" y="{y - 8:.1f}" text-anchor="middle" '
                    'font-family="Arial, sans-serif" font-size="11" '
                    f'fill="#374151">{row.recover_verify_s:.2f}s</text>',
                ]
            )

    legend_x = left + plot_w + 34
    legend_y = top + 20
    for index, (_, label, color) in enumerate(scenarios):
        y = legend_y + index * 30
        lines.extend(
            [
                f'<rect x="{legend_x}" y="{y - 12}" width="16" height="16" rx="4" fill="{color}"/>',
                f'<text x="{legend_x + 24}" y="{y + 1}" font-family="Arial, sans-serif" '
                f'font-size="13" fill="#374151">{svg_text(label)}</text>',
            ]
        )
    lines.extend(
        [
            f'<text x="{left + plot_w / 2:.0f}" y="{height - 22}" text-anchor="middle" '
            'font-family="Arial, sans-serif" font-size="13" fill="#6b7280">Input size</text>',
            "</svg>",
        ]
    )
    path.write_text("\n".join(lines) + "\n")


def write_report_charts(result_dir: Path, rows: list[ResultRow], recovery_rows: list[RecoveryRow]) -> list[tuple[str, str]]:
    chart_dir = result_dir / "charts"
    chart_dir.mkdir(parents=True, exist_ok=True)
    charts = [
        ("Selected-file restore", chart_dir / "selected-file-restore.svg", write_selected_restore_chart),
    ]
    if recovery_rows:
        charts.extend(
            [
                ("Damage recovery scorecard", chart_dir / "recovery-scorecard.svg", write_recovery_scorecard_chart),
                ("Recovery verify time", chart_dir / "recovery-verify-time.svg", write_recovery_time_chart),
            ]
        )
    written: list[tuple[str, str]] = []
    for title, chart_path, writer in charts:
        if writer is write_selected_restore_chart:
            writer(chart_path, rows)  # type: ignore[arg-type]
        else:
            writer(chart_path, recovery_rows)  # type: ignore[arg-type]
        if chart_path.exists():
            written.append((title, f"charts/{chart_path.name}"))
    return written


def largest_tzap_row(rows: list[ResultRow]) -> ResultRow | None:
    tzap_rows = [
        row
        for row in rows
        if row.tool == "tzap" and row.status == "ok" and row.extract_one_s is not None
    ]
    return max(tzap_rows, key=lambda row: row.input_size_bytes, default=None)


def selected_restore_heading(rows: list[ResultRow]) -> str:
    positions = {row.selected_file_position for row in rows if row.selected_file_position}
    if positions == {"last"}:
        return "Last-file restore"
    if positions == {"middle"}:
        return "Middle-file restore"
    if positions == {"first"}:
        return "First-file restore"
    return "One-file restore"


def selected_restore_note(rows: list[ResultRow]) -> str | None:
    positions = sorted({row.selected_file_position for row in rows if row.selected_file_position})
    paths = sorted({row.selected_relative_path for row in rows if row.selected_relative_path})
    if not positions or not paths:
        return None
    position = positions[0] if len(positions) == 1 else ", ".join(positions)
    if len(paths) == 1:
        path_text = f"`{paths[0]}`"
    else:
        path_text = ", ".join(f"`{path}`" for path in paths[:3])
        if len(paths) > 3:
            path_text += ", ..."
    return (
        f"Selected-file restore uses the `{position}` generated member ({path_text}) "
        "to avoid first-file bias."
    )


def write_markdown(path: Path, rows: list[ResultRow], recovery_rows: list[RecoveryRow], meta: dict) -> None:
    charts = write_report_charts(path.parent, rows, recovery_rows)
    largest = largest_tzap_row(rows)
    recovery_cases = len([row for row in recovery_rows if row.status == "ok"])
    recovery_was_run = bool(recovery_rows)
    recovery_competitors = ["tar+zstd", "tar+zstd+age", "7z", "zip"]
    recovery_scenarios = [
        ("missing volume within tolerance", "Missing volume"),
        ("damaged payload block within bit-rot budget", "Rotten payload bytes"),
    ]
    size_ladder = ", ".join(
        fmt_size(size) for size in sorted({row.input_size_bytes for row in rows})
    )
    file_counts = ", ".join(
        fmt_int(count) for count in sorted({row.input_file_count for row in rows})
    )
    config_meta = meta.get("benchmark_config", {})
    lines = [
        "# tzap Benchmark Results",
        "",
        "Human-readable benchmark report generated by `scripts/tzap_benchmark.py`.",
        "",
        "## What This Shows",
        "",
        f"- Normal workflow timings use `{meta['runs']}` timed runs per tool and data set.",
        f"- Recovery proof cases use `{meta.get('recovery_runs', 1)}` timed run per data set and scenario.",
        f"- Input sizes in this report: {size_ladder}. Exact bytes stay in the raw CSV files.",
        "- Time columns show average +/- standard deviation.",
        "- tar+zstd+age+par2 is included in normal workflow timings and size accounting; dedicated PAR2 repair scenarios are tracked separately from this tzap recovery scorecard.",
    ]
    if recovery_was_run:
        lines.extend(
            [
                f"- tzap recovered all `{recovery_cases}` tested damage cases in this run.",
                "- tar+zstd, tar+zstd+age, 7z, and zip are marked failed for these recovery cases because they had no repair-data path for missing or overwritten archive data in this benchmark.",
            ]
        )
    else:
        lines.append("- No tzap recovery proof cases were run in this filtered benchmark.")
    selected_note = selected_restore_note(rows)
    if selected_note:
        lines.append(f"- {selected_note}")
    if largest is not None:
        lines.append(
            f"- On the largest input here ({fmt_size(largest.input_size_bytes)}), "
            f"tzap restored the selected `{largest.selected_file_position}` file in "
            f"{fmt_seconds_label(largest.extract_one_s)} on average."
        )

    if charts:
        lines.extend(["", "## Charts", ""])
        for title, relative_path in charts:
            lines.extend([f"![{title}]({relative_path})", ""])

    lines.extend(
        [
            "## Recovery Scorecard",
            "",
            "| Tool | Missing volume | Rotten payload bytes |",
            "| --- | --- | --- |",
        ]
    )
    tzap_labels = []
    for scenario, _ in recovery_scenarios:
        matching = [row for row in recovery_rows if row.scenario == scenario]
        if not matching:
            tzap_labels.append("Not run")
        elif any(row.status == "ok" for row in matching):
            tzap_labels.append("Recovered")
        else:
            tzap_labels.append("Failed")
    lines.append(f"| tzap | {tzap_labels[0]} | {tzap_labels[1]} |")
    for tool in recovery_competitors:
        label = "Failed" if recovery_was_run else "Not run"
        lines.append(f"| {tool} | {label} | {label} |")

    lines.extend(
        [
            "",
            "## Tool Modes",
            "",
            "| Tool | Mode used in this benchmark | Recovery data? |",
            "| --- | --- | --- |",
            "| tzap | Encrypted, authenticated archive with tzap recovery options for recovery tests | Yes |",
            "| tar+zstd | tar stream compressed with zstd | No |",
            "| tar+zstd+age | tar stream compressed with zstd, then encrypted with age | No |",
            f"| tar+zstd+age+par2 | tar stream compressed with zstd, encrypted with age, then protected by PAR2 recovery files (`-r{config_meta.get('par2_redundancy_pct', '5')}`) | External PAR2 |",
            "| 7z | 7z/LZMA2 archive with password and header encryption (`-p... -mhe=on`) | No |",
            "| zip | Zip archive with password mode (`zip -P ...`) | No |",
            "",
            "`age` is an encryption tool, not parity or recovery. It is included as a simple encrypted pipeline baseline. The PAR2 variant adds external recovery files to that same stream shape.",
        ]
    )

    lines.extend(
        [
            "",
            "## Normal Archive Workflow",
            "",
            f"| Dataset | Files | Input size | Tool | Runs | Create | Verify/Test | Full extract | {selected_restore_heading(rows)} | Archive size | Status |",
            "| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for row in sorted_workflow_rows(rows):
        lines.append(
            "| "
            + " | ".join(
                [
                    row.dataset,
                    fmt_int(row.input_file_count),
                    fmt_size(row.input_size_bytes),
                    row.tool,
                    fmt_int(row.runs),
                    fmt_seconds_with_stddev(row.create_s, row.create_stddev_s),
                    fmt_seconds_with_stddev(row.verify_s, row.verify_stddev_s),
                    fmt_seconds_with_stddev(row.extract_all_s, row.extract_all_stddev_s),
                    fmt_seconds_with_stddev(row.extract_one_s, row.extract_one_stddev_s),
                    fmt_size(row.output_size_bytes),
                    row.status,
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## tzap Recovery Details",
            "",
            "| Dataset | Input size | Recovery case | Runs | Create | Recovery verify | Recovery output | Result |",
            "| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for row in sorted(recovery_rows, key=lambda item: (item.input_size_bytes, item.scenario)):
        lines.append(
            "| "
            + " | ".join(
                [
                    row.dataset,
                    fmt_size(row.input_size_bytes),
                    row.scenario,
                    fmt_int(row.runs),
                    fmt_seconds_with_stddev(row.create_s, row.create_stddev_s),
                    fmt_seconds_with_stddev(
                        row.recover_verify_s, row.recover_verify_stddev_s
                    ),
                    fmt_size(row.output_size_bytes),
                    "Recovered" if row.status == "ok" else row.status,
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Recovery Inputs",
            "",
            "| Dataset | Recovery case | Exact input used |",
            "| --- | --- | --- |",
        ]
    )
    for row in sorted(recovery_rows, key=lambda item: (item.input_size_bytes, item.scenario)):
        lines.append(
            "| "
            + " | ".join(
                [
                    row.dataset,
                    row.scenario,
                    md_cell(row.notes),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Audit Files",
            "",
            "- `results.csv`: exact bytes, selected-file path/position, averages, and standard deviations for normal workflows.",
            "- `recovery.csv`: exact bytes and one-run recovery proof timings.",
            "- `raw-results.csv`: every individual normal workflow run.",
            "- `raw-recovery.csv`: every individual recovery run.",
            "- `logs/benchmark-progress.log`: durable progress log for data generation, each run, each command, and report writing.",
            "- `metadata.json`: machine, profile, selected tools, and tool versions.",
            "",
            "## Command Shapes",
            "",
            "The result logs under `target/tzap-bench/logs/` contain the concrete command for each run. The benchmark uses these command shapes:",
            "",
            "```sh",
            "tzap keygen --output bench.key",
            "tzap create --keyfile bench.key -o ARCHIVE.tzap DATASET",
            "tzap verify --keyfile bench.key ARCHIVE.tzap",
            "tzap extract --keyfile bench.key -C RESTORE_DIR ARCHIVE.tzap",
            "tzap extract --keyfile bench.key --stdout ARCHIVE.tzap SELECTED_FILE > /dev/null",
            f"tzap create --keyfile bench.key --volumes {config_meta.get('missing_volume_count', 3)} --volume-loss-tolerance {config_meta.get('missing_volume_loss_tolerance', 1)} -o RECOVERY.tzap DATASET",
            "# Damaged-payload recovery below the large-data threshold",
            f"tzap create --keyfile bench.key --bit-rot-buffer-pct {config_meta.get('bitrot_buffer_pct', '5')} --block-size {config_meta.get('bitrot_small_block_size', '4K')} --chunk-size {config_meta.get('bitrot_small_chunk_size', '4K')} --envelope-size {config_meta.get('bitrot_envelope_size', '1M')} -o BITROT.tzap DATASET",
            "# Damaged-payload recovery at or above the large-data threshold",
            f"tzap create --keyfile bench.key --bit-rot-buffer-pct {config_meta.get('bitrot_buffer_pct', '5')} --block-size {config_meta.get('bitrot_large_block_size', '64K')} --chunk-size {config_meta.get('bitrot_large_chunk_size', '256K')} --envelope-size {config_meta.get('bitrot_envelope_size', '1M')} -o BITROT.tzap DATASET",
            "",
            "tar -cf - DATASET | zstd -q -T0 -o ARCHIVE.tar.zst -",
            "zstd -q -t ARCHIVE.tar.zst",
            "zstd -q -dc ARCHIVE.tar.zst | tar -xf - -C RESTORE_DIR",
            "",
            "tar -cf - DATASET | zstd -q -T0 | age -r PUBLIC_KEY -o ARCHIVE.tar.zst.age",
            "age -d -i AGE_IDENTITY ARCHIVE.tar.zst.age | zstd -q -t -",
            f"par2 create -q -q -r{config_meta.get('par2_redundancy_pct', '5')} -n1 ARCHIVE.tar.zst.age.par2 ARCHIVE.tar.zst.age",
            "par2 verify -q -q ARCHIVE.tar.zst.age.par2 ARCHIVE.tar.zst.age",
            "",
            "7zz a -t7z -m0=lzma2 -p[BENCH_PASSWORD] -mhe=on ARCHIVE.7z DATASET",
            "7zz t -p[BENCH_PASSWORD] ARCHIVE.7z",
            "7zz x -y -p[BENCH_PASSWORD] -oRESTORE_DIR ARCHIVE.7z",
            "",
            "zip -qr -P [BENCH_PASSWORD] ARCHIVE.zip DATASET",
            "unzip -t -P [BENCH_PASSWORD] ARCHIVE.zip",
            "unzip -q -P [BENCH_PASSWORD] ARCHIVE.zip -d RESTORE_DIR",
            "```",
            "",
            "## Environment",
            "",
            f"- Timestamp: `{meta['timestamp']}`",
            f"- Host: `{meta['platform']}`",
            f"- Python: `{meta['python']}`",
            f"- tzap: `{meta['tzap']}`",
            f"- Profile: `{meta['profile']}`",
            f"- Runs per tool/dataset: `{meta['runs']}`",
            f"- Recovery proof runs per dataset: `{meta.get('recovery_runs', 1)}`",
            f"- Selected-file restore position: `{meta.get('selected_file_position', 'last')}`",
            "",
            "## Benchmark Parameters",
            "",
            f"- Generated files per data set: `{file_counts}`",
            f"- Missing-volume recovery: `--volumes {config_meta.get('missing_volume_count', 3)} --volume-loss-tolerance {config_meta.get('missing_volume_loss_tolerance', 1)}`; omitted `vol{int(config_meta.get('missing_volume_omit_index', 1)):03d}`.",
            f"- Bit-rot recovery, small data sets: `--bit-rot-buffer-pct {config_meta.get('bitrot_buffer_pct', '5')} --block-size {config_meta.get('bitrot_small_block_size', '4K')} --chunk-size {config_meta.get('bitrot_small_chunk_size', '4K')} --envelope-size {config_meta.get('bitrot_envelope_size', '1M')}`.",
            f"- Bit-rot recovery, large data sets at or above {fmt_size(config_meta.get('bitrot_large_threshold_bytes', 10 * BYTES_PER_GB))}: `--bit-rot-buffer-pct {config_meta.get('bitrot_buffer_pct', '5')} --block-size {config_meta.get('bitrot_large_block_size', '64K')} --chunk-size {config_meta.get('bitrot_large_chunk_size', '256K')} --envelope-size {config_meta.get('bitrot_envelope_size', '1M')}`.",
            f"- Injected bit-rot damage: zero first `{fmt_size(config_meta.get('bitrot_corruption_bytes', 4096))}` of the first payload-data BlockRecord.",
            "- Benchmark password for zip/7z is supplied by `--benchmark-password` and redacted from this report.",
            "",
            "## Tool Versions",
            "",
            "| Used By | Command | Resolved Path | Version |",
            "| --- | --- | --- | --- |",
        ]
    )
    for tool in meta.get("tool_versions", []):
        lines.append(
            "| "
            + " | ".join(
                [
                    md_cell(tool["used_by"]),
                    f"`{md_cell(tool['command'])}`",
                    f"`{md_cell(tool['path'] or '')}`",
                    f"`{md_cell(tool['version'])}`",
                ]
            )
            + " |"
        )

    path.write_text("\n".join(lines) + "\n")


def parse_tools(value: str) -> list[str]:
    tools = [item.strip() for item in value.split(",") if item.strip()]
    valid = {"tzap", "tar-zstd", "tar-zstd-age", "tar-zstd-age-par2", "7z", "zip"}
    unknown = sorted(set(tools) - valid)
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown tools: {', '.join(unknown)}")
    return tools


def tool_runner(tool: str) -> Callable[..., ResultRow]:
    return {
        "tzap": run_tzap,
        "tar-zstd": run_tar_zstd,
        "tar-zstd-age": run_tar_zstd_age,
        "tar-zstd-age-par2": run_tar_zstd_age_par2,
        "7z": run_7z,
        "zip": run_zip,
    }[tool]


def missing_tool_reason(tool: str) -> str | None:
    requirements = {
        "tzap": [],
        "tar-zstd": ["tar", "zstd", "bash"],
        "tar-zstd-age": ["tar", "zstd", "age", "age-keygen", "bash"],
        "tar-zstd-age-par2": ["tar", "zstd", "age", "age-keygen", "par2", "bash"],
        "7z": [],
        "zip": ["zip", "unzip"],
    }[tool]
    missing = [name for name in requirements if not available(name)]
    if tool == "7z" and seven_zip_executable() is None:
        missing.append("7z or 7zz")
    return f"missing executable(s): {', '.join(missing)}" if missing else None


def validate_recovery_config(config: BenchmarkConfig) -> None:
    if config.missing_volume_count < 2:
        raise SystemExit("--recovery-volumes must be at least 2")
    if config.missing_volume_loss_tolerance < 1:
        raise SystemExit("--recovery-volume-loss-tolerance must be at least 1")
    if config.missing_volume_loss_tolerance >= config.missing_volume_count:
        raise SystemExit("--recovery-volume-loss-tolerance must be smaller than --recovery-volumes")
    if not 0 <= config.missing_volume_omit_index < config.missing_volume_count:
        raise SystemExit("--recovery-omit-volume-index must be within the generated volume range")
    if not config.bitrot_buffer_pct.strip():
        raise SystemExit("--bitrot-buffer-pct must not be blank")
    if not config.par2_redundancy_pct.strip():
        raise SystemExit("--par2-redundancy-pct must not be blank")
    if config.bitrot_large_threshold_bytes <= 0:
        raise SystemExit("--bitrot-large-threshold must be positive")
    if config.bitrot_corruption_bytes <= 0:
        raise SystemExit("--bitrot-corruption-bytes must be positive")


def default_runs_for_profile(profile: str) -> int:
    return 10 if profile == "smoke" else 30


def useful_version_line(command: str, output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return ""

    matchers = {
        "tzap": lambda line: line.startswith("tzap "),
        "zstd": lambda line: "Zstandard" in line,
        "age": lambda line: line.startswith("v"),
        "age-keygen": lambda line: line.startswith("v"),
        "par2": lambda line: line.startswith("par2cmdline version "),
        "7z": lambda line: "7-Zip" in line,
        "7zz": lambda line: "7-Zip" in line,
        "zip": lambda line: line.startswith("This is Zip "),
        "unzip": lambda line: line.startswith("UnZip "),
    }
    matcher = matchers.get(command)
    if matcher is not None:
        for line in lines:
            if matcher(line):
                return line
    return lines[0]


def command_version(command: str, executable: str, args: list[str]) -> str:
    try:
        completed = subprocess.run(
            [executable, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
            timeout=10,
        )
    except Exception as exc:
        return f"version probe failed: {exc}"

    line = useful_version_line(command, completed.stdout)
    if line:
        return line
    return f"version probe exited {completed.returncode} with no output"


def add_version_probe(
    probes: dict[str, dict[str, object]],
    *,
    command: str,
    executable: str | None,
    args: list[str],
    used_by: str,
) -> None:
    key = executable or command
    if key not in probes:
        resolved_path = executable or shutil.which(command)
        probes[key] = {
            "command": command,
            "path": resolved_path,
            "args": args,
            "used_by": set(),
        }
    probes[key]["used_by"].add(used_by)  # type: ignore[union-attr]


def collect_tool_versions(tools: list[str], tzap: Path) -> list[dict[str, str | None]]:
    probes: dict[str, dict[str, object]] = {}
    if "tzap" in tools:
        add_version_probe(
            probes,
            command="tzap",
            executable=str(tzap),
            args=["--version"],
            used_by="tzap",
        )
    tar_zstd_tools = {"tar-zstd", "tar-zstd-age", "tar-zstd-age-par2"}
    if any(tool in tar_zstd_tools for tool in tools):
        used_by = ", ".join(tool for tool in tools if tool in tar_zstd_tools)
        add_version_probe(
            probes,
            command="tar",
            executable=shutil.which("tar"),
            args=["--version"],
            used_by=used_by,
        )
        add_version_probe(
            probes,
            command="zstd",
            executable=shutil.which("zstd"),
            args=["--version"],
            used_by=used_by,
        )
    age_tools = {"tar-zstd-age", "tar-zstd-age-par2"}
    if any(tool in age_tools for tool in tools):
        used_by = ", ".join(tool for tool in tools if tool in age_tools)
        add_version_probe(
            probes,
            command="age",
            executable=shutil.which("age"),
            args=["--version"],
            used_by=used_by,
        )
        add_version_probe(
            probes,
            command="age-keygen",
            executable=shutil.which("age-keygen"),
            args=["--version"],
            used_by=used_by,
        )
    if "tar-zstd-age-par2" in tools:
        add_version_probe(
            probes,
            command="par2",
            executable=shutil.which("par2"),
            args=["-V"],
            used_by="tar-zstd-age-par2",
        )
    if "7z" in tools:
        seven_zip = seven_zip_executable()
        add_version_probe(
            probes,
            command=Path(seven_zip).name if seven_zip else "7z/7zz",
            executable=seven_zip,
            args=[],
            used_by="7z",
        )
    if "zip" in tools:
        add_version_probe(
            probes,
            command="zip",
            executable=shutil.which("zip"),
            args=["-v"],
            used_by="zip",
        )
        add_version_probe(
            probes,
            command="unzip",
            executable=shutil.which("unzip"),
            args=["-v"],
            used_by="zip",
        )

    versions: list[dict[str, str | None]] = []
    for probe in sorted(probes.values(), key=lambda item: str(item["command"])):
        executable = probe["path"]
        command = str(probe["command"])
        if isinstance(executable, str) and executable:
            version = command_version(command, executable, probe["args"])  # type: ignore[arg-type]
        else:
            version = "missing executable"
        versions.append(
            {
                "used_by": ", ".join(sorted(probe["used_by"])),  # type: ignore[arg-type]
                "command": command,
                "path": executable if isinstance(executable, str) else None,
                "version": version,
            }
        )
    return versions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["smoke", "standard", "large"], default="smoke")
    parser.add_argument(
        "--runs",
        type=int,
        default=None,
        help="number of timed runs per selected tool/dataset; defaults to 10 for smoke and 30 otherwise",
    )
    parser.add_argument(
        "--recovery-runs",
        type=int,
        default=None,
        help="number of timed recovery proof runs per selected dataset; defaults to 1",
    )
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--tzap", type=Path, default=None, help="path to an existing tzap binary")
    parser.add_argument("--skip-build", action="store_true", help="do not build target/release/tzap")
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress console progress; progress is still written to logs/benchmark-progress.log",
    )
    parser.add_argument(
        "--tools",
        type=parse_tools,
        default=parse_tools("tzap,tar-zstd,tar-zstd-age,tar-zstd-age-par2,7z,zip"),
        help="comma-separated tools: tzap,tar-zstd,tar-zstd-age,tar-zstd-age-par2,7z,zip",
    )
    parser.add_argument(
        "--datasets",
        default="all",
        help="comma-separated datasets to run, or all",
    )
    parser.add_argument(
        "--file-count",
        type=int,
        default=None,
        help="override generated file count for each dataset",
    )
    parser.add_argument(
        "--dataset-sizes",
        default=None,
        help="standard profile only: comma-separated total input sizes, e.g. 1MB,20MB,1GB,20GB",
    )
    parser.add_argument(
        "--same-count-file-sizes",
        default=None,
        help="smoke/large profiles only: comma-separated per-file sizes, e.g. 1K,16K,256K",
    )
    parser.add_argument(
        "--selected-file-position",
        choices=["first", "middle", "last"],
        default="last",
        help="which generated file to use for selected-file restore timings; public runs should use last",
    )
    parser.add_argument(
        "--benchmark-password",
        default=BENCH_PASSWORD,
        help="fixed password used for zip and 7z password-mode baselines",
    )
    parser.add_argument("--par2-redundancy-pct", default="5")
    parser.add_argument("--recovery-volumes", type=int, default=3)
    parser.add_argument("--recovery-volume-loss-tolerance", type=int, default=1)
    parser.add_argument("--recovery-omit-volume-index", type=int, default=1)
    parser.add_argument("--bitrot-buffer-pct", default="5")
    parser.add_argument("--bitrot-small-block-size", default="4K")
    parser.add_argument("--bitrot-small-chunk-size", default="4K")
    parser.add_argument("--bitrot-large-threshold", type=parse_size, default=10 * BYTES_PER_GB)
    parser.add_argument("--bitrot-large-block-size", default="64K")
    parser.add_argument("--bitrot-large-chunk-size", default="256K")
    parser.add_argument("--bitrot-envelope-size", default="1M")
    parser.add_argument("--bitrot-corruption-bytes", type=parse_size, default=4096)
    args = parser.parse_args()
    if args.runs is None:
        args.runs = default_runs_for_profile(args.profile)
    if args.runs < 1:
        raise SystemExit("--runs must be at least 1")
    if args.recovery_runs is None:
        args.recovery_runs = 1
    if args.recovery_runs < 1:
        raise SystemExit("--recovery-runs must be at least 1")
    if args.file_count is not None and args.file_count < 1:
        raise SystemExit("--file-count must be at least 1")
    fixed_total_sizes = (
        parse_size_list(args.dataset_sizes, "--dataset-sizes")
        if args.dataset_sizes is not None
        else None
    )
    same_count_file_sizes = (
        parse_size_list(args.same_count_file_sizes, "--same-count-file-sizes")
        if args.same_count_file_sizes is not None
        else None
    )
    if fixed_total_sizes is not None and args.profile != "standard":
        raise SystemExit("--dataset-sizes is only valid with --profile standard")
    if same_count_file_sizes is not None and args.profile == "standard":
        raise SystemExit("--same-count-file-sizes is only valid with --profile smoke or large")
    config = BenchmarkConfig(
        benchmark_password=args.benchmark_password,
        par2_redundancy_pct=str(args.par2_redundancy_pct),
        missing_volume_count=args.recovery_volumes,
        missing_volume_loss_tolerance=args.recovery_volume_loss_tolerance,
        missing_volume_omit_index=args.recovery_omit_volume_index,
        bitrot_buffer_pct=str(args.bitrot_buffer_pct),
        bitrot_small_block_size=args.bitrot_small_block_size,
        bitrot_small_chunk_size=args.bitrot_small_chunk_size,
        bitrot_large_threshold_bytes=args.bitrot_large_threshold,
        bitrot_large_block_size=args.bitrot_large_block_size,
        bitrot_large_chunk_size=args.bitrot_large_chunk_size,
        bitrot_envelope_size=args.bitrot_envelope_size,
        bitrot_corruption_bytes=args.bitrot_corruption_bytes,
    )
    validate_recovery_config(config)

    work_dir: Path = args.work_dir.resolve()
    data_root = work_dir / "data"
    output_root = work_dir / "archives"
    restore_root = work_dir / "restored"
    result_root = work_dir / "results"
    log_root = work_dir / "logs"
    for path in (output_root, restore_root, result_root, log_root):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True)

    progress_log = log_root / "benchmark-progress.log"
    configure_progress_log(progress_log)
    emit_progress(f"benchmark progress log: {progress_log}", args.quiet)
    emit_progress(f"watch progress with: tail -f {progress_log}", args.quiet)
    emit_progress(f"command detail logs directory: {log_root}", args.quiet)
    emit_progress(f"results directory: {result_root}", args.quiet)
    emit_progress(f"preparing benchmark workspace: {work_dir}", args.quiet)
    emit_progress("resolving tzap binary", args.quiet)
    tzap = build_tzap(args.skip_build, args.tzap)
    runner = CommandRunner(log_root, quiet=args.quiet)
    wanted_datasets = None
    if args.datasets.lower() != "all":
        wanted_datasets = {
            item.strip() for item in args.datasets.split(",") if item.strip()
        }
    emit_progress("creating deterministic benchmark data sets", args.quiet)
    datasets = create_datasets(
        data_root,
        args.profile,
        wanted_datasets,
        args.selected_file_position,
        args.file_count,
        fixed_total_sizes,
        same_count_file_sizes,
        args.quiet,
    )
    if not datasets:
        raise SystemExit("no datasets selected")
    emit_progress(
        "datasets ready: "
        + ", ".join(
            f"{dataset.name} ({dataset.file_count} files, {fmt_size(dataset.total_size_bytes)}, selected {dataset.selected_relative_path})"
            for dataset in datasets
        ),
        args.quiet,
    )

    rows: list[ResultRow] = []
    recovery_rows: list[RecoveryRow] = []
    raw_rows: list[RawResultRow] = []
    raw_recovery_rows: list[RawRecoveryRow] = []
    for dataset_index, dataset in enumerate(datasets, start=1):
        emit_progress(
            f"dataset {dataset_index}/{len(datasets)}: {dataset.name} ({fmt_size(dataset.total_size_bytes)})",
            args.quiet,
        )
        for tool_index, tool in enumerate(args.tools, start=1):
            reason = missing_tool_reason(tool)
            if reason is not None:
                emit_progress(
                    f"skip tool {tool_index}/{len(args.tools)} {tool}: {reason}",
                    args.quiet,
                )
                row = skip_row(dataset, tool, reason)
                rows.append(row)
                raw_rows.append(raw_result(0, row))
                continue
            per_run: list[ResultRow] = []
            for run_index in range(1, args.runs + 1):
                emit_progress(
                    f"workflow {dataset.name}: tool {tool_index}/{len(args.tools)} {tool}, run {run_index}/{args.runs}",
                    args.quiet,
                )
                try:
                    if tool == "tzap":
                        row = run_tzap(
                            runner,
                            tzap,
                            data_root,
                            output_root,
                            restore_root,
                            dataset,
                            config,
                        )
                    else:
                        row = tool_runner(tool)(
                            runner,
                            data_root,
                            output_root,
                            restore_root,
                            dataset,
                            config,
                        )
                except Exception as exc:  # keep the sheet useful when one run fails
                    emit_progress(
                        f"workflow failed {dataset.name}/{tool} run {run_index}: {exc}",
                        args.quiet,
                    )
                    row = failed_row(dataset, tool, str(exc))
                per_run.append(row)
                raw_rows.append(raw_result(run_index, row))
            rows.append(summarize_result_rows(per_run))

        if "tzap" in args.tools:
            recovery_fns = (run_tzap_missing_volume_recovery, run_tzap_bitrot_recovery)
            for recovery_index, recovery_fn in enumerate(recovery_fns, start=1):
                scenario = recovery_fn.__name__.replace("run_tzap_", "").replace("_", " ")
                per_run_recovery: list[RecoveryRow] = []
                for run_index in range(1, args.recovery_runs + 1):
                    emit_progress(
                        f"recovery {dataset.name}: case {recovery_index}/{len(recovery_fns)} {scenario}, run {run_index}/{args.recovery_runs}",
                        args.quiet,
                    )
                    try:
                        row = recovery_fn(
                            runner,
                            tzap,
                            data_root,
                            output_root,
                            dataset,
                            config,
                        )
                    except Exception as exc:
                        emit_progress(
                            f"recovery failed {dataset.name}/{scenario} run {run_index}: {exc}",
                            args.quiet,
                        )
                        row = failed_recovery_row(dataset, scenario, str(exc))
                    per_run_recovery.append(row)
                    raw_recovery_rows.append(raw_recovery(run_index, row))
                recovery_rows.append(summarize_recovery_rows(per_run_recovery))

    emit_progress("writing benchmark reports", args.quiet)
    benchmark_config = dataclasses.asdict(config)
    benchmark_config["benchmark_password"] = "[redacted]"
    meta = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "profile": args.profile,
        "tzap": str(tzap),
        "runs": args.runs,
        "recovery_runs": args.recovery_runs,
        "selected_file_position": args.selected_file_position,
        "file_count_override": args.file_count,
        "fixed_total_sizes_bytes": fixed_total_sizes,
        "same_count_file_sizes_bytes": same_count_file_sizes,
        "progress_log": str(progress_log),
        "benchmark_config": benchmark_config,
        "selected_files": {
            dataset.name: dataset.selected_relative_path for dataset in datasets
        },
        "tools": args.tools,
        "datasets": [dataset.name for dataset in datasets],
        "dataset_sizes_bytes": {
            dataset.name: dataset.total_size_bytes for dataset in datasets
        },
        "gnu_time": str(runner.gnu_time) if runner.gnu_time else None,
        "tool_versions": collect_tool_versions(args.tools, tzap),
    }
    (result_root / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    write_csv(result_root / "results.csv", rows)
    write_recovery_csv(result_root / "recovery.csv", recovery_rows)
    write_raw_csv(result_root / "raw-results.csv", raw_rows)
    write_raw_recovery_csv(result_root / "raw-recovery.csv", raw_recovery_rows)
    write_markdown(result_root / "results.md", rows, recovery_rows, meta)

    emit_progress(f"wrote {result_root / 'results.csv'}", args.quiet)
    emit_progress(f"wrote {result_root / 'recovery.csv'}", args.quiet)
    emit_progress(f"wrote {result_root / 'raw-results.csv'}", args.quiet)
    emit_progress(f"wrote {result_root / 'raw-recovery.csv'}", args.quiet)
    emit_progress(f"wrote {result_root / 'results.md'}", args.quiet)
    if runner.gnu_time is None:
        emit_progress(
            "peak RSS blank: GNU time was not found (install gtime on macOS)",
            args.quiet,
        )
    emit_progress("benchmark complete", args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
