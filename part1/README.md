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
5. abort channel oracles (statement templates):
   - `error(...)`
   - `assert(...)`
   - divide-by-zero
   - modulo-by-zero
   - out-of-bounds read
6. nontermination channel oracles (two loop templates)
7. timing channel oracle with adaptive calibration:
   - tries several burn-loop sizes
   - also tries a short-circuit expression timing template
   - uses a `//@label H` accumulator to avoid low-write implicit-flow rejection
   - checks baseline vs. high-input separation
   - uses repeated median measurements and majority voting

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

### Notes

- The script exits with code `0` only when all requested servers are recovered.
- If one server is intentionally secure, unresolved servers are reported and the
  script exits nonzero so you can investigate manually.
- If timing is noisy on a shared machine, increase `--timing-repeats` (for
  example to `5`) and possibly `--timing-timeout`.
- The harness also auto-calibrates per-server timeouts from a no-op baseline,
  then scales timing timeout accordingly.
- Any recovered candidate is re-verified against the server using `return input;`
  (including nearby off-by-one candidates) before writing `flow_serve<n>.txt`.
- Some servers reject nearly all nontrivial programs as `insecure`; in that case
  the harness reports those channels quickly and focuses on probes that still parse
  and execute.
