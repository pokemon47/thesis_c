# Poseidon2 Pipeline Contract

## Summary
This document freezes the current Poseidon2 contract between Besu, Noir, and the thesis benchmark pipeline before any circuit changes.

The current state is:
- Besu has the Poseidon2 proof-path hashing path implemented.
- Noir compatibility vectors exist for the raw permutation, field sponge, and byte-hash adapter.
- The thesis `account_inclusion` circuit is still Keccak-only.
- Poseidon2 rows in the benchmark pipeline are currently proxy rows, not full in-circuit Poseidon2 proofs.

## Poseidon2 Semantics
The Poseidon2 byte-hash contract used by the pipeline is:

- BN254 scalar field
- width 4, rate 3, capacity 1
- 8 full rounds, 56 partial rounds
- 31-byte chunks
- little-endian chunk-to-field conversion
- zero-padded final partial chunk
- no explicit byte-length field
- no domain separator
- output serialized as 32-byte big-endian

This is the semantics boundary that Besu and the Noir harness agree on today.

## Besu Scope
The experimental selector is:

```text
-Dbesu.experimental.proof-path-hashing=poseidon2
```

When enabled, it affects:
- account trie key hashing
- storage trie key hashing
- proof node identity hashing
- trie node hashing

It does not affect:
- EVM `KECCAK256`
- block hash / header hash
- transaction hash
- address derivation
- `codeHash`

That makes the Poseidon2 path a proof-path and trie-hash concern only, not a general-purpose hash replacement.

## Thesis C Current Limitation
The current thesis circuit state is intentionally incomplete for Poseidon2:

- `circuits/src/hash_poseidon2.nr` is a placeholder
- `circuits/src/account_inclusion.nr` is Keccak-only
- `thesis_c/benchmark/runner.py` emits `proxy` rows for Poseidon2 `account_inclusion` with reason `proxy_hash_cost_poseidon2_not_in_circuit`

So today, Poseidon2 account-inclusion benchmark rows measure pipeline cost and routing behavior, not an honest Poseidon2 circuit proof.

## Benchmark Row Meaning
The benchmark pipeline already distinguishes:
- `ok`
- `missing_dataset`
- `proxy`
- `error`

For Poseidon2 account inclusion:
- `proxy` means the hash-cost arm is being tracked intentionally even though the circuit is not yet implemented.
- `missing_dataset` means the Poseidon2 dataset arm was not available.
- `ok` remains reserved for a real executed proof path.

## Future-Proofing Note
`account_inclusion` is the first proof statement used to validate the pipeline, not the final thesis scope.

The Poseidon2 byte-hashing module and benchmark routing should be treated as reusable infrastructure so later proof statements can reuse the same hash semantics and dataset conventions, including:
- `storage_slot_inclusion`
- `storage_slot_non_inclusion`
- `historical_value_proof`
- `contract_storage_proof`
- `multi_slot_storage_proof`

The implementation should avoid hardcoding account-inclusion-specific assumptions where a small abstraction would make later storage-related proofs easier.

## Next Implementation Decision
For the next circuit phase, prefer separate circuits or separate entrypoints for Keccak and Poseidon2 benchmark arms.

Why:
- benchmark rows and witness assumptions stay unambiguous
- `hash_variant_id` branching does not leak into one mixed circuit while Poseidon2 is still maturing
- benchmark comparisons stay cleaner and easier to interpret

## Assumptions
- `docs/` did not previously exist in `thesis_c`, so this file is newly added.
- The Noir compatibility record in `test_noir/poseidon2_noir_compatibility.md` remains unchanged.
- No code changes or benchmark runs are required for this document-only update.
