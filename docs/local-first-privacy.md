**Maintainer:** Frangel Raúl Crespo Barrera
**Last verified:** 2026-10-02
**Scope:** local file access, report/dashboard output, telemetry, retention, and cleanup.

| Field | Current record |
|---|---|
| Status | Local-first intent documented; claims about egress must follow implementation evidence. |
| Evidence | `didileak/`, `tests/test_detectors.py`, `tests/test_security_regression.py`, `docs/`, `pyproject.toml`, `.github/workflows/ci.yml`. |
| Verification | `pytest -q`; inspect file access and output paths when changing detectors or reporters. |
| Owner | Repository owner. |
| Limitations | This page does not prove absence of telemetry or leakage in every future feature. |

Use synthetic credentials and PII in tests. Do not expose detected secrets in logs, dashboards, fixtures, or reports. Define retention and cleanup for caches and generated artifacts.
