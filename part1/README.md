## Lab 2 Part 1 attack harness

This directory contains a practical automation tool for **Part 1 (The Attack)**.

Because the official binaries (`~mfredrik/bin/c0_serve1` .. `c0_serve5`) are only
available on the CMU `linux.andrew.cmu.edu` machines, run this tool there.

### What it does

`extract_secrets.py` tries multiple attack strategies, in this order, for each server:

1. direct explicit flow (`return secret;`)
2. implicit-flow boolean oracle (`if (secret < input) ...`)
3. abort channel oracles (multiple templates):
   - `error(...)`
   - `assert(...)`
   - divide-by-zero
   - modulo-by-zero
   - out-of-bounds read
4. nontermination channel oracles (two loop templates)
5. timing channel oracle with adaptive calibration:
   - tries several burn-loop sizes
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
