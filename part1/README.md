## Lab 2 Part 1 attack harness

This directory contains a practical automation tool for **Part 1 (The Attack)**.

Because the official binaries (`~mfredrik/bin/c0_serve1` .. `c0_serve5`) are only
available on the CMU `linux.andrew.cmu.edu` machines, run this tool there.

### What it does

`extract_secrets.py` tries multiple attack strategies, in this order, for each server:

1. direct explicit flow (`return secret;`)
2. implicit-flow boolean oracle (`if (secret < input) ...`)
3. expression-level abort oracles (short-circuit/int-cast templates):
   - guarded divide-by-zero
   - guarded modulo-by-zero
   - guarded out-of-bounds read
   - int-cast guards (`int gate = secret < input; 1 / gate`)
4. bitwise abort oracles:
   - reads each secret bit via expression-driven abort behavior
   - includes classic arithmetic and expression-guarded variants
   - reconstructs a 62-bit candidate and verifies by exact-match query
5. strict expression fuzz suite (strict-policy mode):
   - enumerates many expression forms around `&&`/`||`, guard polarity/order,
     and arithmetic/OOB payloads
   - auto-detects informative endpoint behavior and upgrades to binary-search
     oracle recovery when possible
6. abort channel oracles (statement templates):
   - `error(...)`
   - `assert(...)`
   - divide-by-zero
   - modulo-by-zero
   - out-of-bounds read
7. nontermination channel oracles (two loop templates)
8. timing channel oracle with adaptive calibration:
   - tries several burn-loop sizes
   - also tries a secret-arithmetic short-circuit timing template
   - includes a strict-friendly, secret-gated allocation-timing template
   - checks baseline vs. high-input separation
   - uses repeated median measurements and stronger majority voting
   - if a timing probe is rejected but endpoint result kinds differ, it
     opportunistically upgrades to a kind-oracle binary search

If a strategy recovers a secret, the script writes:

- `flow_serve1.txt`
- `flow_serve2.txt`
- ...

into your chosen output directory.

### Usage

```bash
python3 part1/extract_secrets.py --userid <andrew_id> --outdir .
```

Example:

```bash
python3 part1/extract_secrets.py --userid jdoe --outdir .
```

This attempts servers 1..5 by default and writes `flow_serve<n>.txt` files in `.`.

### Optional flags

- `--servers 1 3 4` attack only a subset
- `--query-timeout 1.2` timeout (seconds) for non-timing probes
- `--timing-timeout 12.0` timeout (seconds) for timing probes
- `--timing-repeats 3` repeated timing samples per probe (median used)
- `--debug` print per-strategy diagnostics explaining why a strategy was rejected
- `--deep` enable a slower, broader strict-mode search (more fuzz probes, no
  early-stop in strict fuzz, and deeper strict-policy exploration)

### Notes

- The script exits with code `0` only when all requested servers are recovered.
- If one server is intentionally secure, unresolved servers are reported and the
  script exits nonzero so you can investigate manually.
- If timing is noisy on a shared machine, increase `--timing-repeats` (for
  example to `5`) and possibly `--timing-timeout`.
- The harness also auto-calibrates per-server timeouts from a no-op baseline,
  then scales timing timeout accordingly.
- Any recovered candidate is re-verified before writing `flow_serve<n>.txt`.
  The verifier first tries a constant-return checker (`return <candidate>;`) and
  falls back to `return input;` if needed; nearby off-by-one candidates are also
  checked.
- Timing-derived candidates now require stronger confidence checks before they
  are accepted: boundary consistency voting plus repeated exact-match
  verification passes.
- Some servers reject nearly all nontrivial programs as `insecure`; in that case
  the harness reports those channels quickly and focuses on probes that still parse
  and execute.
- In strict-policy mode, the harness now also tries a dedicated bitwise template
  set before timing to catch arithmetic abort/failure behavior that generic fuzzing
  can miss.
