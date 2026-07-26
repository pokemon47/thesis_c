# UltraHONK Benchmark Run

- Run ID: `ultrahonk_smoke_20260726T024913Z`
- Repository revision: `0d8bf3d9554136d599a116c40a525b8a29b84a17`
- Status: `completed`
- Logical specifications: `4`
- Physical result rows: `4`
- Successful rows: `4`
- Failed rows: `0`

## Rows
- `account_inclusion` / `keccak256` / `ultra_honk`: `ok` (verification_ok=True)
- `account_inclusion` / `poseidon2` / `ultra_honk`: `ok` (verification_ok=True)
- `account_inclusion_anchored` / `keccak256` / `ultra_honk`: `ok` (verification_ok=True)
- `balance_verification_anchored_poseidon2` / `poseidon2` / `ultra_honk`: `ok` (verification_ok=True)

## Environment

- Python: `/Users/doodleaks/Developer/Thesis/.venv/bin/python` (3.14.2)
- Nargo: `/Users/doodleaks/.nargo/bin/nargo` (1.0.0-beta.22)
- BB: `/Users/doodleaks/.bb/bb` (5.0.0-nightly.20260522)
- Poseidon2 helper: `/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}`

Timings from different laptops should be compared only when machine hardware is treated as an experimental variable.
