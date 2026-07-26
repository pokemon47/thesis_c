# Native Proof Benchmark

This benchmark measures client-observed Besu `eth_getProof` acquisition latency
for account proofs with an optionally empty storage-key list. It includes Besu
database lookup, trie proof construction, JSON serialization, local RPC
transport, and client response parsing. It does not isolate internal trie time.

Both supported variants use the standard `eth_getProof` JSON-RPC method:

```json
{"jsonrpc":"2.0","method":"eth_getProof","params":["0xADDRESS",[],"0xBLOCK"],"id":1}
```

Run against already-started nodes. Process startup, readiness, and cold-cache
measurements are future work. Outputs are independent of the SNARK benchmark.

```bash
python -m thesis_c.benchmark.native_proof --variant keccak256 \
  --rpc-url http://127.0.0.1:8545 --block 0x9 --address 0x... \
  --warmups 3 --repeats 10 --output-dir benchmarks/native_runs/<RUN_ID>
```

The future online total is native acquisition plus preparation, witness
generation, and SNARK proving. Compilation is excluded as reusable work.
