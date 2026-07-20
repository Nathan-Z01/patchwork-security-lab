"""Contract tests for the public Patchwork HTTP adapter."""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from importlib import import_module
from threading import Event, get_ident

import pytest
from fastapi.testclient import TestClient

api_module = import_module("patchwork_api.app")


@pytest.fixture(autouse=True)
def reset_api_state(monkeypatch):
    api_module._SCANS.clear()
    monkeypatch.setattr(api_module, "_scan_source_impl", None)
    monkeypatch.setattr(api_module, "_scan_url_impl", None)
    monkeypatch.setattr(api_module, "_stock_research_impl", None)
    monkeypatch.setattr(api_module, "_stock_demo_research_impl", None)


@pytest.fixture
def client():
    return TestClient(api_module.create_app())


class FakeReport:
    def __init__(self, findings, **metadata):
        self.findings = findings
        self.completeness = metadata.pop("completeness", "complete")
        self.metadata = metadata

    def to_dict(self):
        return {
            "completeness": self.completeness,
            "findings": self.findings,
            "metadata": self.metadata,
            "limitations": ["Only supported source files were inspected."],
        }


class FakeStockResult:
    def __init__(self, payload):
        self.payload = payload

    def to_dict(self):
        return self.payload


def stock_payload(*, symbol="NOVA", benchmark="SPY", horizon_days=20, sample_data=False):
    return {
        "symbol": symbol,
        "benchmark": benchmark,
        "as_of": "2026-07-17",
        "horizon_days": horizon_days,
        "opinion": "bullish",
        "probability_outperform": 0.64,
        "confidence": "moderate",
        "sample_data": sample_data,
        "rationale": [
            {
                "feature": "relative_momentum_20d",
                "label": "20-day relative momentum",
                "value": 0.081,
                "direction": "positive",
                "explanation": "The stock recently outpaced its benchmark.",
            }
        ],
        "limitations": ["Historical relationships may not persist."],
        "disclaimer": "Research output only; not financial advice.",
        "model": {
            "name": "SignalLab gradient boosting ensemble",
            "version": "1.0",
            "trained_through": "2024-12-20",
            "training_rows": 744,
            "symbols": [symbol, benchmark],
            "feature_count": 12,
            "evaluation": {
                "test_start": "2025-01-02",
                "test_end": "2026-06-18",
                "samples": 240,
                "effective_windows": 12,
                "accuracy": 0.58,
                "balanced_accuracy": 0.57,
                "brier_score": 0.24,
                "constant_brier": 0.25,
                "roc_auc": 0.61,
                "base_rate": 0.51,
            },
        },
    }


def test_health_endpoint(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "patchwork-api"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in response.headers["permissions-policy"]


def test_capabilities_describe_local_only_stock_research(client):
    response = client.get("/api/capabilities")

    assert response.status_code == 200
    stocks = response.json()["stock_research"]
    assert stocks["enabled"] is True
    assert stocks["local_csv_only"] is True
    assert stocks["network_fetching"] is False
    assert stocks["horizon_days"] == {"minimum": 5, "maximum": 60}


def test_sync_scanner_runs_outside_the_event_loop_thread():
    observed = {}

    def sync_scanner(target, **options):
        observed["scanner_thread"] = get_ident()
        return {"target": target, "options": options}

    async def invoke():
        observed["event_loop_thread"] = get_ident()
        return await api_module._invoke_scanner(sync_scanner, "target", limit=2)

    result = asyncio.run(invoke())

    assert observed["scanner_thread"] != observed["event_loop_thread"]
    assert result == {"target": "target", "options": {"limit": 2}}


def test_async_scanner_remains_supported_on_the_event_loop():
    observed = {}

    async def async_scanner(target, **options):
        await asyncio.sleep(0)
        observed["scanner_thread"] = get_ident()
        return {"target": target, "options": options}

    async def invoke():
        observed["event_loop_thread"] = get_ident()
        return await api_module._invoke_scanner(async_scanner, "target", limit=3)

    result = asyncio.run(invoke())

    assert observed["scanner_thread"] == observed["event_loop_thread"]
    assert result == {"target": "target", "options": {"limit": 3}}


def test_demo_scan_is_labeled_and_exportable(client):
    response = client.post("/api/scans/demo")

    assert response.status_code == 200
    scan = response.json()
    assert scan["target_type"] == "demo"
    assert scan["metadata"]["sample_data"] is True
    assert scan["summary"]["total"] == len(scan["findings"])
    assert scan["summary"]["critical"] >= 1

    export = client.get("/api/scans/{}/export/sarif".format(scan["id"]))
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("application/sarif+json")
    sarif = export.json()
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(scan["findings"])


def test_scan_store_evicts_the_oldest_entry(client, monkeypatch):
    monkeypatch.setattr(api_module, "MAX_STORED_SCANS", 3)

    scan_ids = [client.post("/api/scans/demo").json()["id"] for _ in range(4)]

    assert len(api_module._SCANS) == 3
    assert scan_ids[0] not in api_module._SCANS
    assert client.get(f"/api/scans/{scan_ids[0]}").status_code == 404
    listed_ids = [item["id"] for item in client.get("/api/scans").json()]
    assert listed_ids == list(reversed(scan_ids[1:]))


def test_source_scan_delegates_to_public_core_api(client, monkeypatch, tmp_path):
    observed = {}
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    project = source_root / "example"
    project.mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))

    def fake_scan_source(path, **options):
        observed["path"] = path
        observed["options"] = options
        return FakeReport(
            [
                {
                    "id": "finding-1",
                    "rule_id": "AISEC-TEST-001",
                    "title": "Unsafe model output sink",
                    "severity": "high",
                    "confidence": "confirmed",
                    "category": "output handling",
                    "description": "Model output reaches an HTML sink.",
                    "location": {"path": "src/view.py", "line": 17},
                    "evidence": "render_html(answer)",
                    "remediation": "Sanitize generated HTML before rendering.",
                }
            ],
            files_scanned=12,
            checks_run=8,
        )

    monkeypatch.setattr(api_module, "_scan_source_impl", fake_scan_source)
    response = client.post("/api/scans/source", json={"path": "example"})

    assert response.status_code == 200
    scan = response.json()
    assert observed == {
        "path": str(project.resolve()),
        "options": {"max_files": 5000},
    }
    assert scan["summary"]["high"] == 1
    assert scan["summary"]["confirmed"] == 1
    assert scan["summary"]["files_scanned"] == 12
    assert scan["status"] == "completed"
    assert scan["coverage"] == {
        "completeness": "complete",
        "files_scanned": 12,
        "pages_scanned": None,
        "skipped": None,
    }
    assert scan["target"] == str(project.resolve())
    assert scan["findings"][0]["location"]["line"] == 17
    assert scan["findings"][0]["evidence"][0]["value"] == "render_html(answer)"


def test_source_scan_rejects_parent_traversal(client, monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    monkeypatch.setattr(api_module, "_scan_source_impl", lambda path, **options: FakeReport([]))

    response = client.post("/api/scans/source", json={"path": "../outside"})

    assert response.status_code == 403
    assert "PATCHWORK_WORKSPACE_ROOT" in response.json()["detail"]


def test_source_scan_rejects_symlink_escape(client, monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (source_root / "linked-outside").symlink_to(outside, target_is_directory=True)
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    monkeypatch.setattr(api_module, "_scan_source_impl", lambda path, **options: FakeReport([]))

    response = client.post("/api/scans/source", json={"path": "linked-outside"})

    assert response.status_code == 403


def test_source_scan_rejects_missing_target(client, monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    monkeypatch.setattr(api_module, "_scan_source_impl", lambda path, **options: FakeReport([]))

    response = client.post("/api/scans/source", json={"path": "missing"})

    assert response.status_code == 422


def test_stock_analysis_uses_local_csv_and_normalizes_response(client, monkeypatch, tmp_path):
    observed = {}
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    data_path = source_root / "prices.csv"
    data_path.write_text("date,symbol,close\n2026-07-17,NOVA,42\n", encoding="utf-8")
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))

    def fake_research(path, symbol, **options):
        observed["path"] = path
        observed["symbol"] = symbol
        observed["options"] = options
        return FakeStockResult(stock_payload(symbol=symbol, benchmark=options["benchmark"]))

    monkeypatch.setattr(api_module, "_stock_research_impl", fake_research)
    response = client.post(
        "/api/stocks/analyze",
        json={
            "data_path": "prices.csv",
            "symbol": "nova",
            "benchmark": "spy",
            "horizon_days": 20,
        },
    )

    assert response.status_code == 200
    opinion = response.json()
    assert observed == {
        "path": data_path.resolve(),
        "symbol": "NOVA",
        "options": {"benchmark": "SPY", "horizon_days": 20},
    }
    assert len(opinion["id"]) == 36
    assert opinion["symbol"] == "NOVA"
    assert opinion["opinion"] == "bullish"
    assert opinion["probability_outperform"] == 0.64
    assert opinion["sample_data"] is False
    assert opinion["model"]["evaluation"]["roc_auc"] == 0.61


def test_stock_demo_uses_bundled_research_without_a_request_body(client, monkeypatch):
    observed = {}

    def fake_demo(symbol, **options):
        observed["symbol"] = symbol
        observed["options"] = options
        return FakeStockResult(
            stock_payload(
                symbol=symbol,
                benchmark=options["benchmark"],
                horizon_days=options["horizon_days"],
                sample_data=True,
            )
        )

    monkeypatch.setattr(api_module, "_stock_demo_research_impl", fake_demo)
    response = client.post("/api/stocks/demo")

    assert response.status_code == 200
    assert observed == {
        "symbol": "SYNTH_A",
        "options": {"benchmark": "SYNTH_MKT", "horizon_days": 20},
    }
    assert response.json()["sample_data"] is True


def test_stock_demo_real_core_satisfies_the_public_contract(client):
    response = client.post("/api/stocks/demo")

    assert response.status_code == 200
    opinion = response.json()
    assert opinion["symbol"] == "SYNTH_A"
    assert opinion["benchmark"] == "SYNTH_MKT"
    assert opinion["sample_data"] is True
    assert opinion["opinion"] in {"bullish", "neutral", "bearish"}
    assert 0.0 <= opinion["probability_outperform"] <= 1.0
    assert opinion["symbol"] in opinion["model"]["symbols"]
    assert opinion["model"]["evaluation"]["constant_brier"] >= 0.0
    assert opinion["model"]["evaluation"]["effective_windows"] >= 1


@pytest.mark.parametrize("horizon_days", [5, 60])
def test_stock_demo_real_core_supports_public_horizon_bounds(client, horizon_days):
    response = client.post(
        "/api/stocks/demo",
        json={
            "symbol": "SYNTH_A",
            "benchmark": "SYNTH_MKT",
            "horizon_days": horizon_days,
        },
    )

    assert response.status_code == 200
    assert response.json()["horizon_days"] == horizon_days


def test_stock_contract_accepts_zero_effective_windows_for_a_weak_dataset(
    client, monkeypatch
):
    payload = stock_payload(
        symbol="SYNTH_A",
        benchmark="SYNTH_MKT",
        sample_data=True,
    )
    payload["opinion"] = "neutral"
    payload["confidence"] = "low"
    payload["model"]["evaluation"]["effective_windows"] = 0
    monkeypatch.setattr(
        api_module,
        "_stock_demo_research_impl",
        lambda *args, **kwargs: FakeStockResult(payload),
    )

    response = client.post("/api/stocks/demo")

    assert response.status_code == 200
    assert response.json()["model"]["evaluation"]["effective_windows"] == 0


@pytest.mark.parametrize(
    ("data_path", "expected_status"),
    [
        ("../outside.csv", 403),
        ("missing.csv", 422),
        ("prices.txt", 422),
        ("data", 422),
    ],
)
def test_stock_analysis_rejects_unsafe_or_non_csv_targets(
    client, monkeypatch, tmp_path, data_path, expected_status
):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    (tmp_path / "outside.csv").write_text("private", encoding="utf-8")
    (source_root / "prices.txt").write_text("not csv", encoding="utf-8")
    (source_root / "data").mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    monkeypatch.setattr(
        api_module,
        "_stock_research_impl",
        lambda *args, **kwargs: pytest.fail("unsafe target reached the model"),
    )

    response = client.post(
        "/api/stocks/analyze",
        json={"data_path": data_path, "symbol": "NOVA"},
    )

    assert response.status_code == expected_status


def test_stock_analysis_rejects_unreadable_csv(client, monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    data_path = source_root / "private.csv"
    data_path.write_text("secret", encoding="utf-8")
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    real_access = api_module.os.access
    monkeypatch.setattr(
        api_module.os,
        "access",
        lambda path, mode: False if path == data_path.resolve() else real_access(path, mode),
    )

    response = client.post(
        "/api/stocks/analyze",
        json={"data_path": "private.csv", "symbol": "NOVA"},
    )

    assert response.status_code == 403
    assert "not readable" in response.json()["detail"].lower()


@pytest.mark.parametrize(
    "payload",
    [
        {"data_path": "prices.csv", "symbol": "../../etc/passwd"},
        {"data_path": "prices.csv", "symbol": "NOVA", "benchmark": "SPY;curl"},
        {"data_path": "prices.csv", "symbol": "NOVA", "horizon_days": 4},
        {"data_path": "prices.csv", "symbol": "NOVA", "horizon_days": 61},
        {"data_path": "prices.csv", "symbol": "NOVA", "api_key": "do-not-accept"},
    ],
)
def test_stock_analysis_rejects_invalid_or_extra_inputs(client, payload):
    response = client.post("/api/stocks/analyze", json=payload)

    assert response.status_code == 422


def test_stock_domain_error_is_safe_and_does_not_leak_secrets(client, monkeypatch, tmp_path):
    from signallab.errors import DataValidationError

    secret = "private-row-and-provider-token"
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    (source_root / "prices.csv").write_text("date,symbol,close\n", encoding="utf-8")
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))

    def invalid_dataset(*args, **kwargs):
        raise DataValidationError(secret)

    monkeypatch.setattr(api_module, "_stock_research_impl", invalid_dataset)
    response = client.post(
        "/api/stocks/analyze",
        json={"data_path": "prices.csv", "symbol": "NOVA"},
    )

    assert response.status_code == 422
    assert secret not in response.text
    assert "csv contents" in response.json()["detail"].lower()


def test_stock_result_serialization_error_is_a_correlated_failure(client, monkeypatch):
    secret = "serialization-secret"

    class BrokenResult:
        def to_dict(self):
            raise ValueError(secret)

    monkeypatch.setattr(
        api_module,
        "_stock_demo_research_impl",
        lambda *args, **kwargs: BrokenResult(),
    )
    response = client.post("/api/stocks/demo")

    assert response.status_code == 502
    assert len(response.headers["x-patchwork-error-id"]) == 32
    assert secret not in response.text


@pytest.mark.parametrize(
    "result",
    [
        object(),
        FakeStockResult({}),
        FakeStockResult({**stock_payload(), "probability_outperform": float("nan")}),
        FakeStockResult({**stock_payload(), "as_of": "2026-99-99"}),
        FakeStockResult({**stock_payload(), "unexpected_secret": "must-not-leak"}),
    ],
)
def test_stock_result_contract_fails_closed(client, monkeypatch, result):
    monkeypatch.setattr(api_module, "_stock_demo_research_impl", lambda *args, **kwargs: result)

    response = client.post("/api/stocks/demo")

    assert response.status_code == 502
    assert len(response.headers["x-patchwork-error-id"]) == 32
    assert "must-not-leak" not in response.text


@pytest.mark.parametrize(
    "violation",
    ["reversed_test", "late_training", "early_opinion", "missing_symbol"],
)
def test_stock_result_provenance_fails_closed(client, monkeypatch, violation):
    payload = stock_payload()
    evaluation = payload["model"]["evaluation"]
    if violation == "reversed_test":
        evaluation["test_start"] = "2026-06-19"
    elif violation == "late_training":
        payload["model"]["trained_through"] = evaluation["test_start"]
    elif violation == "early_opinion":
        payload["as_of"] = "2025-01-01"
    else:
        payload["model"]["symbols"] = ["SPY"]
    monkeypatch.setattr(
        api_module,
        "_stock_demo_research_impl",
        lambda *args, **kwargs: FakeStockResult(payload),
    )

    response = client.post("/api/stocks/demo")

    assert response.status_code == 502
    assert len(response.headers["x-patchwork-error-id"]) == 32


def test_unexpected_stock_error_is_correlated_and_not_leaked(client, monkeypatch, caplog):
    secret = "internal-stock-training-secret"

    def exploding_demo(*args, **kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(api_module, "_stock_demo_research_impl", exploding_demo)
    caplog.set_level(logging.ERROR, logger="patchwork_api.app")
    response = client.post("/api/stocks/demo")

    assert response.status_code == 502
    error_id = response.headers["x-patchwork-error-id"]
    assert len(error_id) == 32
    assert error_id in response.json()["detail"]
    assert secret not in response.text
    assert any(error_id in record.getMessage() for record in caplog.records)


def test_url_scan_is_delegated_without_an_adapter_network_request(client, monkeypatch):
    observed = {}

    async def fake_scan_url(url, **options):
        observed["url"] = url
        observed["options"] = options
        return FakeReport([], checks_run=5)

    monkeypatch.setattr(api_module, "_scan_url_impl", fake_scan_url)
    response = client.post(
        "/api/scans/url",
        json={"url": "https://example.com/app", "timeout_seconds": 4.5},
    )

    assert response.status_code == 200
    assert observed == {
        "url": "https://example.com/app",
        "options": {"timeout": 4.5},
    }
    assert response.json()["target_type"] == "url"
    assert response.json()["summary"]["total"] == 0


def test_failed_url_scan_exposes_incomplete_coverage_and_unsuccessful_sarif(client, monkeypatch):
    async def failed_scan_url(url, **options):
        return {
            "target": url,
            "scanner": "url",
            "completeness": "failed",
            "summary": {
                "total_findings": 0,
                "files_scanned": 0,
                "pages_scanned": 0,
                "skipped": 1,
            },
            "findings": [],
            "warnings": ["The root page could not be fetched."],
        }

    monkeypatch.setattr(api_module, "_scan_url_impl", failed_scan_url)
    response = client.post("/api/scans/url", json={"url": "https://example.com/"})

    assert response.status_code == 200
    scan = response.json()
    assert scan["status"] == "failed"
    assert scan["summary"]["total"] == 0
    assert scan["summary"]["pages_scanned"] == 0
    assert scan["summary"]["skipped"] == 1
    assert scan["coverage"] == {
        "completeness": "failed",
        "files_scanned": 0,
        "pages_scanned": 0,
        "skipped": 1,
    }
    assert scan["limitations"] == ["The root page could not be fetched."]

    sarif = client.get(f"/api/scans/{scan['id']}/export/sarif").json()
    invocation = sarif["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["properties"]["status"] == "failed"
    assert invocation["properties"]["completeness"] == "failed"


def test_partial_source_scan_exposes_coverage(client, monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))

    def partial_scan_source(path, **options):
        return {
            "target": path,
            "scanner": "source",
            "completeness": "partial",
            "summary": {"files_scanned": 3, "pages_scanned": 0, "skipped": 2},
            "findings": [],
            "warnings": ["Two files were unreadable."],
        }

    monkeypatch.setattr(api_module, "_scan_source_impl", partial_scan_source)
    response = client.post("/api/scans/source", json={"path": "."})

    assert response.status_code == 200
    scan = response.json()
    assert scan["status"] == "partial"
    assert scan["coverage"]["completeness"] == "partial"
    assert scan["coverage"]["files_scanned"] == 3
    assert scan["coverage"]["skipped"] == 2


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        {},
        {"completeness": "unknown", "findings": []},
        {"completeness": "complete", "findings": {}},
    ],
)
def test_malformed_scanner_output_fails_closed(client, monkeypatch, tmp_path, malformed):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    monkeypatch.setattr(api_module, "_scan_source_impl", lambda path, **options: malformed)

    response = client.post("/api/scans/source", json={"path": "."})

    assert response.status_code == 502
    assert len(response.headers["x-patchwork-error-id"]) == 32
    assert "scanner could not complete" in response.json()["detail"].lower()
    assert not api_module._SCANS


def test_configured_workspace_does_not_read_process_cwd(monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))

    def forbidden_cwd():
        raise PermissionError("current directory is unreadable")

    monkeypatch.setattr(api_module.Path, "cwd", forbidden_cwd)

    assert api_module._resolve_source_target(".") == source_root.resolve()


def test_scan_capacity_rejects_immediately_without_blocking_health(monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    monkeypatch.setenv("PATCHWORK_MAX_CONCURRENT_SCANS", "1")
    entered = Event()
    release = Event()

    def blocking_scan_source(path, **options):
        entered.set()
        assert release.wait(timeout=5)
        return {"completeness": "complete", "findings": []}

    monkeypatch.setattr(api_module, "_scan_source_impl", blocking_scan_source)
    application = api_module.create_app()

    with ExitStack() as stack:
        first_client = stack.enter_context(TestClient(application))
        second_client = stack.enter_context(TestClient(application))
        executor = stack.enter_context(ThreadPoolExecutor(max_workers=1))
        first = executor.submit(
            first_client.post,
            "/api/scans/source",
            json={"path": "."},
        )
        try:
            assert entered.wait(timeout=2)
            saturated = second_client.post("/api/scans/source", json={"path": "."})
            health = second_client.get("/api/health")
        finally:
            release.set()

        assert saturated.status_code == 429
        assert saturated.headers["retry-after"] == "1"
        assert saturated.json()["detail"] == "The scanner is at capacity. Try again shortly."
        assert health.status_code == 200
        assert first.result(timeout=5).status_code == 200


def test_stock_training_shares_capacity_limit_with_scans(monkeypatch, tmp_path):
    source_root = tmp_path / "workspace"
    source_root.mkdir()
    data_path = source_root / "prices.csv"
    data_path.write_text("date,symbol,close\n2026-07-17,NOVA,42\n", encoding="utf-8")
    monkeypatch.setenv("PATCHWORK_WORKSPACE_ROOT", str(source_root))
    monkeypatch.setenv("PATCHWORK_MAX_CONCURRENT_SCANS", "1")
    entered = Event()
    release = Event()

    def blocking_research(path, symbol, **options):
        entered.set()
        assert release.wait(timeout=5)
        return FakeStockResult(stock_payload(symbol=symbol, benchmark=options["benchmark"]))

    monkeypatch.setattr(api_module, "_stock_research_impl", blocking_research)
    monkeypatch.setattr(
        api_module,
        "_scan_source_impl",
        lambda *args, **kwargs: FakeReport([]),
    )
    application = api_module.create_app()

    with ExitStack() as stack:
        first_client = stack.enter_context(TestClient(application))
        second_client = stack.enter_context(TestClient(application))
        executor = stack.enter_context(ThreadPoolExecutor(max_workers=1))
        first = executor.submit(
            first_client.post,
            "/api/stocks/analyze",
            json={"data_path": "prices.csv", "symbol": "NOVA"},
        )
        try:
            assert entered.wait(timeout=2)
            saturated = second_client.post("/api/scans/source", json={"path": "."})
            health = second_client.get("/api/health")
        finally:
            release.set()

        assert saturated.status_code == 429
        assert saturated.headers["retry-after"] == "1"
        assert health.status_code == 200
        assert first.result(timeout=5).status_code == 200


def test_unexpected_scanner_error_is_correlated_logged_and_not_leaked(client, monkeypatch, caplog):
    secret = "super-secret-provider-token"

    async def exploding_scan_url(url, **options):
        raise RuntimeError(secret)

    monkeypatch.setattr(api_module, "_scan_url_impl", exploding_scan_url)
    caplog.set_level(logging.ERROR, logger="patchwork_api.app")

    response = client.post("/api/scans/url", json={"url": "https://example.com/"})

    assert response.status_code == 502
    error_id = response.headers["x-patchwork-error-id"]
    assert len(error_id) == 32
    assert all(character in "0123456789abcdef" for character in error_id)
    assert error_id in response.json()["detail"]
    assert secret not in response.text
    matching_records = [record for record in caplog.records if error_id in record.getMessage()]
    assert len(matching_records) == 1
    assert matching_records[0].exc_info is not None


@pytest.mark.parametrize(
    "url",
    [
        "example.com",
        "file:///etc/passwd",
        "https://user:password@example.com/",
    ],
)
def test_url_endpoint_rejects_malformed_or_credentialed_urls(client, url):
    response = client.post("/api/scans/url", json={"url": url})

    assert response.status_code == 422


def test_unknown_export_is_not_found(client):
    response = client.get("/api/scans/not-present/export/json")

    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found in this server session."


def test_dashboard_dist_resolution_prefers_override_then_source_then_package(tmp_path):
    override = tmp_path / "override"
    repo_root = tmp_path / "repo"
    source_dist = repo_root / "apps" / "dashboard" / "dist"
    package_root = tmp_path / "installed" / "patchwork_api"
    package_dist = package_root / "dashboard"
    for candidate in (override, source_dist, package_dist):
        candidate.mkdir(parents=True)
        (candidate / "index.html").write_text(candidate.name, encoding="utf-8")

    assert (
        api_module._resolve_dashboard_dist(
            environ={"PATCHWORK_DASHBOARD_DIST": str(override)},
            repo_root=repo_root,
            package_root=package_root,
        )
        == override.resolve()
    )
    assert (
        api_module._resolve_dashboard_dist(
            environ={},
            repo_root=repo_root,
            package_root=package_root,
        )
        == source_dist.resolve()
    )

    (source_dist / "index.html").unlink()
    assert (
        api_module._resolve_dashboard_dist(
            environ={"PATCHWORK_DASHBOARD_DIST": str(tmp_path / "missing")},
            repo_root=repo_root,
            package_root=package_root,
        )
        == package_dist.resolve()
    )


def test_dashboard_dist_resolution_requires_an_index(tmp_path):
    repo_root = tmp_path / "repo"
    package_root = tmp_path / "installed" / "patchwork_api"
    (repo_root / "apps" / "dashboard" / "dist").mkdir(parents=True)
    (package_root / "dashboard").mkdir(parents=True)

    assert (
        api_module._resolve_dashboard_dist(
            environ={},
            repo_root=repo_root,
            package_root=package_root,
        )
        is None
    )


def test_dashboard_dist_override_serves_spa_and_preserves_api_404(monkeypatch, tmp_path):
    dashboard_dist = tmp_path / "dashboard-dist"
    dashboard_dist.mkdir()
    assets_dir = dashboard_dist / "assets"
    assets_dir.mkdir()
    (dashboard_dist / "index.html").write_text(
        "<!doctype html><title>Sentinel test dashboard</title>", encoding="utf-8"
    )
    (assets_dir / "app.js").write_text("console.log('sentinel')", encoding="utf-8")
    monkeypatch.setenv("PATCHWORK_DASHBOARD_DIST", str(dashboard_dist))
    static_client = TestClient(api_module.create_app())

    root_response = static_client.get("/")
    nested_response = static_client.get("/review/sample")
    asset_response = static_client.get("/assets/app.js")
    api_response = static_client.get("/api/not-present")

    assert root_response.status_code == 200
    assert "Sentinel test dashboard" in root_response.text
    assert nested_response.status_code == 200
    assert asset_response.status_code == 200
    assert api_response.status_code == 404
    assert api_response.json()["detail"] == "API route not found."
    for response in (root_response, nested_response, asset_response):
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-frame-options"] == "DENY"
        assert "camera=()" in response.headers["permissions-policy"]
        policy = response.headers["content-security-policy"]
        assert "default-src 'self'" in policy
        assert "frame-ancestors 'none'" in policy
        assert "object-src 'none'" in policy
