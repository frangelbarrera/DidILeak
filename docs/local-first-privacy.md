# Local-first privacy model

The intended privacy boundary is local analysis: document which paths are read, which data is retained, what is never transmitted, and which permissions are required. Logs and dashboard output must not expose detected secrets or personal data.

Use synthetic credentials and PII in tests. Define cleanup and retention for reports and caches. Claims about telemetry or data egress should remain limited to behavior verified by the implementation and CI.
