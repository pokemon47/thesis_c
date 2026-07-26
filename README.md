# Thesis C: Noir + Barretenberg Benchmarks

This repository implements Thesis C as a direct continuation of historical Ethereum
storage proof research.

## Thesis Focus

Primary question:

> Does replacing Keccak-256 with Poseidon2 improve the efficiency of historical
> Ethereum storage proofs in zk-SNARK systems?

Secondary question:

> How do UltraPLONK and UltraHONK compare when proving historical Ethereum proof
> statements?

## Scope Policy

This project is intentionally benchmark-first. It is **not** a production Ethereum
zk prover.

When there is a tradeoff between complete Ethereum compatibility and producing
meaningful Poseidon2 vs Keccak benchmarks, this repository prioritizes
benchmarkability and reproducibility.

## Required Experiment Matrix

- `keccak256` + `ultra_plonk`
- `keccak256` + `ultra_honk`
- `poseidon2` + `ultra_plonk`
- `poseidon2` + `ultra_honk`

## Must-Have Deliverables

1. Reusable `eth_getProof` loading.
2. Baseline proof verification (Python verifier adapter).
3. Noir pipeline (`nargo`) for witness generation.
4. Barretenberg pipeline (`bb`) for proving and verification.
5. CSV and JSON benchmark output with timing and size metrics.

## Statement Targets

Should-have:

- Account inclusion
- Balance verification
- CodeHash verification
- EOA activity proof (nonce increase between two historical proofs)

Stretch:

- Storage slot membership
- Full in-circuit Keccak verification

## Project Layout

- `thesis_c/`: Python orchestration pipeline (loading, baseline verify, benchmarking).
- `circuits/`: Noir circuits and program metadata.
- `datasets/`: Input proofs grouped by hash variant.
- `benchmarks/`: Generated benchmark artifacts.

## Toolchain

Expected tools:

- Python 3.11+
- `nargo` (Noir)
- `bb` (Barretenberg CLI)

The Python pipeline calls `nargo` and `bb` as subprocesses and records runtimes,
memory snapshots, and proof artifact metadata.

## Current Account Inclusion Stage

The first real proof implemented in this repository is:

- **baseline-verified bounded account inclusion proof**

Statement:

> I know a valid account proof showing that `accountAddress` exists under
> `stateRoot`.

Important scope note:

- This stage uses Python baseline verification and bounded pre-normalized witness data.
- It is not yet a full generalized Ethereum MPT verifier covering every edge case.
- Noir `storage_slot_membership` and `eoa_activity` have isolated package routes;
  their current proof-language limits remain bounded as documented.
- Python-side storage proof checks are available via `thesis-c verify-storage`.

### Bounded assumptions

- `MAX_ACCOUNT_PROOF_NODES = 4` (current sample proof shape: branch, branch, branch, leaf)
- `MAX_ACCOUNT_NODE_BYTES = 544`
- `ACCOUNT_PATH_NIBBLES = 64`
- `MAX_LEAF_PATH_NIBBLES = 64`
- Decoded node metadata is pre-normalized in Python before witness emission.

### Trust boundary (bounded normalized MPT)

| Component | Status | Notes |
| --- | --- | --- |
| Root equality and node hash chain | Fully constrained in Noir | `keccak(node_rlp)` chain is enforced from root to leaf node hash. |
| Branch child binding | Fully constrained in Noir (normalized) | Circuit takes normalized `3 x 16 x 32` branch child arrays and enforces selected child at `path_nibble` for each branch hop. |
| Account leaf fields binding | Fully constrained in Noir | Authenticated terminal bytes are parsed through canonical nested account RLP constraints. |
| Leaf path compact decoding | Constrained in Noir | Compact-path flags, suffix consumption, and terminal linkage are checked in the circuit. |
| Full RLP decoding (branch and leaf semantics) | Constrained for supported proof language | Canonical account and storage RLP parsing is bounded to the documented proof shapes. |
| Poseidon2 in-circuit hashing | Supported in isolated packages | Poseidon2 uses the configured byte/Field contract; the Java adapter remains Python preparation infrastructure. |

### Verification metadata emitted in benchmark rows

- `branch_child_binding = in_circuit`
- `leaf_account_binding = in_circuit_or_partial`
- `rlp_decoding = python_preprocessed`
- `mpt_verification_level = bounded_normalized_mpt`

## Dataset Validation Workflow

Before benchmark runs, validate Poseidon2 datasets:

```bash
thesis-c dataset discover --path datasets/poseidon2
thesis-c dataset validate --path datasets/poseidon2 --hash poseidon2
thesis-c dataset manifest --path datasets/poseidon2 --hash poseidon2
```

Optional cross-variant consistency checks against Keccak samples:

```bash
thesis-c dataset validate --path datasets/poseidon2 --hash poseidon2 --reference datasets/keccak
```

The manifest command writes `datasets/poseidon2/manifest.json` by default when run
from this project root.

## Four-Cell Benchmark Commands

Run account inclusion matrix with explicit dataset paths:

```bash
thesis-c benchmark \
  --input datasets/keccak \
  --input-keccak datasets/keccak \
  --input-poseidon2 datasets/poseidon2 \
  --statements account_inclusion \
  --hashes keccak256,poseidon2 \
  --backends ultra_plonk,ultra_honk
```

Equivalent per-cell runs:

```bash
# Keccak + UltraPLONK
thesis-c benchmark --input datasets/keccak --input-keccak datasets/keccak --statements account_inclusion --hashes keccak256 --backends ultra_plonk

# Keccak + UltraHONK
thesis-c benchmark --input datasets/keccak --input-keccak datasets/keccak --statements account_inclusion --hashes keccak256 --backends ultra_honk

# Poseidon2 + UltraPLONK
thesis-c benchmark --input datasets/keccak --input-poseidon2 datasets/poseidon2 --statements account_inclusion --hashes poseidon2 --backends ultra_plonk

# Poseidon2 + UltraHONK
thesis-c benchmark --input datasets/keccak --input-poseidon2 datasets/poseidon2 --statements account_inclusion --hashes poseidon2 --backends ultra_honk
```

### Status field semantics

Benchmark rows include `status`:

- `ok`: proof executed and verified.
- `missing_dataset`: dataset path missing or empty for that hash arm.
- `proxy`: row intentionally emitted as fallback proxy (e.g., hash circuit not yet in-circuit).
- `error`: execution failed for a real attempted run.

## Python Storage Proof Verification

`thesis-c` includes a Python-only storage proof verifier:

```bash
thesis-c verify-storage --input datasets/keccak --hash keccak256
```

Optional JSON report:

```bash
thesis-c verify-storage --input sample_proof.json --hash keccak256 --output-json storage_report.json
```

What `verify-storage` checks per payload:

1. Account proof validity (same baseline account trie walk as `thesis-c baseline`).
2. Account-leaf `storageRoot` extraction and optional cross-check against payload `storageHash`.
3. Each `storageProof` entry trie walk from `storageRoot`, plus storage value decoding and
   comparison to the payload `value`.

This command runs entirely in Python and does not invoke `nargo` or `bb`.

## Dataset Validation Framework

`thesis-c` also includes a complete dataset validation command for raw `eth_getProof`
artifacts:

```bash
thesis-c validate-dataset --input datasets/keccak --hash keccak256
```

Validation stages:

1. Strict schema validation for accepted `eth_getProof` JSON shapes.
2. Account/storage proof node shape checks (hex, RLP, MPT node arity).
3. Account proof bounded checks (current `MAX_ACCOUNT_PROOF_NODES` / `MAX_ACCOUNT_NODE_BYTES` limits).
4. Account proof walk and account-leaf consistency checks against payload fields.
5. Storage proof walk and slot value checks for each storage entry.

Reports:

- `validation.json`: summary and per-payload issue details.
- `validation.csv`: flat issue rows for spreadsheet/analysis tooling.

By default reports are written to `validation/reports/<utc_timestamp>/`.
Override with:

```bash
thesis-c validate-dataset \
  --input datasets/keccak \
  --hash keccak256 \
  --output-dir validation/reports/manual-run
```

Exit codes:

- `0`: validation completed with no error-severity issues.
- `1`: validation completed but found one or more error-severity issues.
- `2`: invalid input path / report I/O / runtime execution failure.
