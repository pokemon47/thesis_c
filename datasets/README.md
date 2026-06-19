# Dataset Layout

Place `eth_getProof` JSON files under one of:

- `datasets/keccak/`
- `datasets/poseidon2/`

Accepted JSON formats:

1. Single JSON-RPC response object with `result`.
2. Single bare `result` object.
3. Array of either of the above.

Optional metadata:

- `blockNumber` (hex or decimal) at top level.
- `stateRoot` in result object.

For Python storage verification (`thesis-c verify-storage`), each payload must also contain
at least one `storageProof` entry with:

- `key` (slot key, accepted as hex quantity/data and normalized to 32 bytes before hashing),
- `value` (expected storage value as hex quantity or decimal string),
- `proof` (array of hex-encoded trie nodes for that slot).

EOA activity statements require at least two proofs for the same address at different
block heights.

## Poseidon2 Hash Adapter Configuration

Poseidon2 baseline checks require one of:

- `THESIS_C_POSEIDON2_CMD`: command template invoked as a subprocess.
- `THESIS_C_POSEIDON2_VECTORS`: JSON file mapping `input_hex -> digest_hex`.

If neither is configured, Poseidon2 dataset validation reports a hash-configuration
error.

## Dataset Management Commands

Run from `SNARK/thesis_c`:

```bash
# Discover files and payloads
thesis-c dataset discover --path datasets/poseidon2

# Validate metadata, hash config, and consistency
thesis-c dataset validate --path datasets/poseidon2 --hash poseidon2

# Optional cross-variant consistency against keccak dataset
thesis-c dataset validate \
  --path datasets/poseidon2 \
  --hash poseidon2 \
  --reference datasets/keccak

# Generate manifest artifact
thesis-c dataset manifest --path datasets/poseidon2 --hash poseidon2
```

`dataset manifest` writes `manifest.json` in the dataset directory by default.

## Dataset Validation Reports

Use `validate-dataset` for full schema + proof integrity validation:

```bash
thesis-c validate-dataset --input datasets/keccak --hash keccak256
```

This command validates:

- schema and required `eth_getProof` fields,
- account proof shape and node-size bounds,
- account proof walk consistency (`nonce`, `balance`, `storageHash`, `codeHash`, optional `stateRoot`),
- storage proof walk consistency for each `storageProof` entry.

Outputs:

- `validation.json` (summary + detailed records),
- `validation.csv` (flat issue rows).

Default output directory: `validation/reports/<utc_timestamp>/`.
Set an explicit output directory with `--output-dir`.

## Manifest Output

Generated manifests include:

- Discovery summary (`files`, `payloads`, missing/parse errors).
- Metadata validation (`address`, proof hex, bounded account-proof checks).
- Hash validation (`keccak256` or `poseidon2`, baseline verifier output).
- Consistency findings (duplicates, missing block numbers, optional reference diffs).
- Aggregate summary counts and a `has_errors` flag.

## Benchmark behavior

- If `datasets/poseidon2/` is missing or empty, Poseidon2 matrix rows are emitted with
  `status=missing_dataset`.
- The benchmark runner does not crash when Poseidon2 data is absent.
- Poseidon2 account-inclusion proving remains `status=proxy` until a real Noir
  Poseidon2 circuit is implemented.
