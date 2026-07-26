"""Client-observed Besu ``eth_getProof`` benchmark.

This module deliberately measures only the native RPC acquisition layer. It does
not include SNARK preparation, witness generation, proving, or verification.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import statistics
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class NativeRequest:
    variant: str
    rpc_url: str
    block: str
    address: str
    storage_keys: tuple[str, ...] = ()
    client_id: str = "unknown"
    database_id: str = "unknown"


@dataclass
class NativeMeasurement:
    run_id: str
    timestamp: str
    variant: str
    client_id: str
    rpc_method: str
    rpc_url: str
    database_id: str
    block: str
    address: str
    storage_keys: list[str]
    cache_condition: str
    classification: str
    repeat_index: int
    latency_ms: float | None
    response_size_bytes: int
    account_proof_node_count: int
    storage_proof_entry_count: int
    storage_proof_node_count: int
    status: str
    rpc_error_code: int | None
    rpc_error_message: str | None
    response_validation_ok: bool
    error: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"{label} must be a 0x-prefixed hex string")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ValueError(f"{label} is not valid hex") from exc
    return value


def validate_response(response: Any, request: NativeRequest) -> dict[str, int]:
    if not isinstance(response, dict) or response.get("jsonrpc") != "2.0":
        raise ValueError("response is not a JSON-RPC 2.0 object")
    if response.get("error") is not None:
        raise ValueError("JSON-RPC response contains an error")
    result = response.get("result")
    if not isinstance(result, dict):
        raise ValueError("response result is not an object")
    returned_address = result.get("address")
    if returned_address is not None and returned_address.lower() != request.address.lower():
        raise ValueError("response address does not match request")
    account_proof = result.get("accountProof")
    if not isinstance(account_proof, list) or not account_proof:
        raise ValueError("accountProof must be a non-empty list")
    for node in account_proof:
        _hex(node, "accountProof node")
    storage = result.get("storageProof")
    if not isinstance(storage, list) or len(storage) != len(request.storage_keys):
        raise ValueError("storageProof does not match requested storage keys")
    storage_nodes = 0
    for entry, key in zip(storage, request.storage_keys, strict=True):
        if not isinstance(entry, dict) or str(entry.get("key", "")).lower() != key.lower():
            raise ValueError("storageProof key does not match request")
        proof = entry.get("proof")
        if not isinstance(proof, list):
            raise ValueError("storageProof proof is not a list")
        for node in proof:
            _hex(node, "storageProof node")
        storage_nodes += len(proof)
    return {
        "account_proof_node_count": len(account_proof),
        "storage_proof_entry_count": len(storage),
        "storage_proof_node_count": storage_nodes,
    }


def rpc_call(request: NativeRequest, timeout_s: float = 30.0) -> tuple[Any, int]:
    body = json.dumps({"jsonrpc": "2.0", "method": "eth_getProof", "params": [request.address, list(request.storage_keys), request.block], "id": 1}).encode()
    http_request = urllib.request.Request(request.rpc_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(http_request, timeout=timeout_s) as handle:
        raw = handle.read()
    return json.loads(raw.decode()), len(raw)


def check_endpoint(rpc_url: str, timeout_s: float = 2.0) -> dict[str, Any]:
    """Check JSON-RPC readiness without including the request in measurements."""
    body = json.dumps({"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1}).encode()
    request = urllib.request.Request(rpc_url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout_s) as handle:
        response = json.loads(handle.read().decode())
    if response.get("error") is not None or not response.get("result"):
        raise RuntimeError(f"RPC endpoint is not ready: {response}")
    return response


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    low, high = math.floor(rank), math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def aggregate(rows: list[NativeMeasurement]) -> dict[str, Any]:
    by_variant: dict[str, list[NativeMeasurement]] = {}
    for row in rows:
        by_variant.setdefault(row.variant, []).append(row)
    output = {}
    for variant, items in sorted(by_variant.items()):
        successful = [item for item in items if item.status == "ok" and item.latency_ms is not None]
        latencies = [item.latency_ms for item in successful]
        sizes = [item.response_size_bytes for item in successful]
        nodes = [item.account_proof_node_count for item in successful]
        output[variant] = {
            "count": len(items), "successful_count": len(successful), "failed_count": len(items) - len(successful),
            "mean_latency_ms": statistics.mean(latencies) if latencies else None,
            "median_latency_ms": statistics.median(latencies) if latencies else None,
            "min_latency_ms": min(latencies) if latencies else None,
            "max_latency_ms": max(latencies) if latencies else None,
            "stddev_latency_ms": statistics.stdev(latencies) if len(latencies) > 1 else 0.0 if latencies else None,
            "p95_latency_ms": _percentile(latencies, 0.95),
            "mean_response_size_bytes": statistics.mean(sizes) if sizes else None,
            "median_response_size_bytes": statistics.median(sizes) if sizes else None,
            "mean_account_proof_node_count": statistics.mean(nodes) if nodes else None,
            "median_account_proof_node_count": statistics.median(nodes) if nodes else None,
        }
    return output


def _measurement(request: NativeRequest, run_id: str, cache: str, classification: str, index: int, timeout_s: float) -> NativeMeasurement:
    started = time.perf_counter_ns()
    size = 0
    try:
        response, size = rpc_call(request, timeout_s)
        rpc_error = response.get("error") if isinstance(response, dict) else None
        if rpc_error is not None:
            return NativeMeasurement(run_id=run_id, timestamp=_now(), variant=request.variant, client_id=request.client_id, rpc_method="eth_getProof", rpc_url=request.rpc_url, database_id=request.database_id, block=request.block, address=request.address, storage_keys=list(request.storage_keys), cache_condition=cache, classification=classification, repeat_index=index, latency_ms=None, response_size_bytes=size, account_proof_node_count=0, storage_proof_entry_count=0, storage_proof_node_count=0, status="error", rpc_error_code=rpc_error.get("code"), rpc_error_message=rpc_error.get("message"), response_validation_ok=False, error="JSON-RPC error")
        metrics = validate_response(response, request)
        latency = (time.perf_counter_ns() - started) / 1_000_000
        return NativeMeasurement(run_id, _now(), request.variant, request.client_id, "eth_getProof", request.rpc_url, request.database_id, request.block, request.address, list(request.storage_keys), cache, classification, index, latency, size, **metrics, status="ok", rpc_error_code=None, rpc_error_message=None, response_validation_ok=True)
    except urllib.error.HTTPError as exc:
        return NativeMeasurement(run_id, _now(), request.variant, request.client_id, "eth_getProof", request.rpc_url, request.database_id, request.block, request.address, list(request.storage_keys), cache, classification, index, None, size, 0, 0, 0, "error", exc.code, str(exc), False, str(exc))
    except Exception as exc:  # benchmark rows retain failures for aggregate reporting
        return NativeMeasurement(run_id, _now(), request.variant, request.client_id, "eth_getProof", request.rpc_url, request.database_id, request.block, request.address, list(request.storage_keys), cache, classification, index, None, size, 0, 0, 0, "error", None, None, False, str(exc))


def run(request: NativeRequest, output_dir: Path, warmups: int = 3, repeats: int = 10, timeout_s: float = 30.0, save_responses: bool = False) -> dict[str, Any]:
    if warmups < 0 or repeats <= 0:
        raise ValueError("warmups must be non-negative and repeats must be positive")
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = output_dir.name
    rows = []
    for index in range(warmups):
        _measurement(request, run_id, "warm", "warmup", index, timeout_s)
    for index in range(repeats):
        rows.append(_measurement(request, run_id, "warm", "measured", index, timeout_s))
    payload = {"run_id": run_id, "rpc_method": "eth_getProof", "cache_condition": "warm", "warmups": warmups, "repeats": repeats, "rows": [asdict(row) for row in rows], "aggregates": aggregate(rows)}
    (output_dir / "native_proof_benchmark.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    fields = list(asdict(rows[0]).keys())
    with (output_dir / "native_proof_benchmark.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader(); writer.writerows(asdict(row) for row in rows)
    (output_dir / "summary.json").write_text(json.dumps({"run_id": run_id, "aggregates": payload["aggregates"]}, indent=2, sort_keys=True) + "\n")
    (output_dir / "environment.json").write_text(json.dumps({"python": platform.python_version(), "platform": platform.platform(), "rpc_method": "eth_getProof", "raw_responses_saved": save_responses}, indent=2, sort_keys=True) + "\n")
    (output_dir / "manifest.json").write_text(json.dumps({"run_id": run_id, "request": asdict(request), "warmups": warmups, "repeats": repeats, "cache_condition": "warm", "raw_responses_saved": save_responses}, indent=2, sort_keys=True) + "\n")
    lines = ["# Native Proof Benchmark", "", "Client-observed `eth_getProof` latency; includes RPC and JSON serialization overhead.", "", f"Run: `{run_id}`", "", "## Aggregates"]
    for variant, stats in payload["aggregates"].items():
        lines.append(f"- `{variant}`: {stats['successful_count']}/{stats['count']} successful, median {stats['median_latency_ms']} ms, p95 {stats['p95_latency_ms']} ms, median response {stats['median_response_size_bytes']} bytes, median account nodes {stats['median_account_proof_node_count']}")
    (output_dir / "report.md").write_text("\n".join(lines) + "\n")
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark native Besu eth_getProof acquisition")
    parser.add_argument("--variant", choices=("keccak256", "poseidon2"), required=True)
    parser.add_argument("--rpc-url", required=True)
    parser.add_argument("--block", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--storage-key", action="append", default=[])
    parser.add_argument("--client-id", default="unknown")
    parser.add_argument("--database-id", default="unknown")
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--save-responses", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    request = NativeRequest(args.variant, args.rpc_url, args.block, args.address, tuple(args.storage_key), args.client_id, args.database_id)
    run(request, args.output_dir, args.warmups, args.repeats, args.timeout, args.save_responses)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
