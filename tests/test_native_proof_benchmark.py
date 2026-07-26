from __future__ import annotations

from pathlib import Path

import pytest

from thesis_c.benchmark.native_proof import NativeRequest, aggregate, run, validate_response


ADDRESS = "0x" + "11" * 20
REQUEST = NativeRequest("keccak256", "http://127.0.0.1:0", "0x9", ADDRESS)


def response(address: str = ADDRESS) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "address": address,
            "accountProof": ["0x01", "0xabcd"],
            "storageProof": [],
        },
    }


def test_validate_response_and_storage_counts():
    request = NativeRequest("poseidon2", "http://local", "0x9", ADDRESS, ("0x01",))
    result = response()
    result["result"]["storageProof"] = [{"key": "0x01", "value": "0x0", "proof": ["0x00"]}]
    assert validate_response(result, request) == {
        "account_proof_node_count": 2,
        "storage_proof_entry_count": 1,
        "storage_proof_node_count": 1,
    }


@pytest.mark.parametrize("bad", [{"jsonrpc": "2.0", "result": {}}, {"jsonrpc": "2.0", "error": {"code": -1}}])
def test_validate_response_rejects_invalid_shapes(bad):
    with pytest.raises(ValueError):
        validate_response(bad, REQUEST)


def test_run_excludes_warmups_and_writes_outputs(monkeypatch, tmp_path: Path):
    request = NativeRequest("keccak256", "http://mock", "0x9", ADDRESS, client_id="test", database_id="db")
    monkeypatch.setattr("thesis_c.benchmark.native_proof.rpc_call", lambda *_args, **_kwargs: (response(), 123))
    payload = run(request, tmp_path / "native-test", warmups=1, repeats=2)
    assert len(payload["rows"]) == 2
    assert all(row["classification"] == "measured" for row in payload["rows"])
    assert payload["aggregates"]["keccak256"]["successful_count"] == 2
    for name in ("native_proof_benchmark.csv", "native_proof_benchmark.json", "summary.json", "report.md", "manifest.json", "environment.json"):
        assert (tmp_path / "native-test" / name).exists()


def test_aggregate_statistics():
    from thesis_c.benchmark.native_proof import NativeMeasurement

    rows = [NativeMeasurement("r", "t", "poseidon2", "c", "eth_getProof", "u", "d", "0x9", ADDRESS, [], "warm", "measured", i, float(i + 1), 100 + i, 2, 0, 0, "ok", None, None, True) for i in range(4)]
    stats = aggregate(rows)["poseidon2"]
    assert stats["count"] == 4
    assert stats["successful_count"] == 4
    assert stats["mean_latency_ms"] == 2.5
    assert stats["median_latency_ms"] == 2.5
    assert stats["min_latency_ms"] == 1.0
    assert stats["max_latency_ms"] == 4.0
    assert stats["p95_latency_ms"] == pytest.approx(3.85)
