# Poseidon2 Pipeline Contract

## Summary
This document records the Poseidon2 contract between Besu, Noir, and the thesis benchmark pipeline.

The current state is:
- Besu has the Poseidon2 proof-path hashing path implemented.
- Noir compatibility vectors exist for the raw permutation, field sponge, and byte-hash adapter.
- Dedicated Poseidon2 circuit packages now exist for account inclusion, balance verification, and stored codeHash verification.
- EOA activity is a supplied-root two-state statement and remains real-dataset gated per hash variant.

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

## Thesis C Circuit Scope
The original `circuits/` package remains the Keccak account-inclusion package.
Poseidon2 is implemented through separate packages and entrypoints so each benchmark arm has unambiguous witness and circuit assumptions.

Current Poseidon2 packages preserve the Besu byte-hash semantics above and use Field-form root/linkage where needed:

- `circuits_poseidon2`
- `circuits_balance_poseidon2`
- `circuits_codehash_poseidon2`
- `circuits_eoa_activity_poseidon2`
- `circuits_storage_slot_inclusion_poseidon2`

Unsupported future statements may still use `proxy` or `error` rows, but supported Poseidon2 account-inclusion, balance, and codeHash routes are no longer proxy-only.

## Benchmark Row Meaning
The benchmark pipeline already distinguishes:
- `ok`
- `missing_dataset`
- `proxy`
- `error`

For supported Poseidon2 statements:
- `ok` means a real isolated circuit/proving path executed and verified.
- `proxy` is reserved for unsupported or deliberately deferred statement/hash combinations.
- `missing_dataset` means the dataset arm was not available.
- `error` means preparation, circuit execution, proving, or verification failed.

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

## Freeze Status

The base statement families and storage benchmark policy are frozen in
`docs/task3f_freeze.md`. This document remains a semantics boundary record;
benchmark results and toolchain availability are recorded separately.
