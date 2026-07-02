"""Tests for the detector engine."""
from __future__ import annotations

from didileak.detectors import RULES, DetectorEngine, _luhn_valid, _mask
from didileak.models import Message, Severity


def _scan(text: str) -> list:
    engine = DetectorEngine()
    return engine.scan_message(Message(role="user", content=text, provider="test"))


def test_rule_ids_unique():
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids))


def test_mask_short_value():
    assert _mask("ab") == "***"
    assert _mask("abc") == "a*c"
    assert _mask("abcdefgh") == "abcd...efgh"


def test_luhn_valid_visa_test_number():
    assert _luhn_valid("4111111111111111") is True


def test_luhn_invalid_random():
    assert _luhn_valid("1234567890123456") is False


def test_aws_access_key_detected():
    hits = _scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE2")
    assert any(h.rule_id == "aws-access-token" for h in hits)


def test_aws_access_key_placeholder_rejected():
    # AKIATESTEXAMPLE000000 should be rejected by validator
    hits = _scan("key=AKIATESTEXAMPLE000000")
    assert not any(h.rule_id == "aws-access-token" for h in hits)


def test_github_pat_detected():
    hits = _scan("GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
    assert any(h.rule_id == "github-pat" for h in hits)


def test_github_oauth_detected():
    hits = _scan("token=gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
    assert any(h.rule_id == "github-oauth" for h in hits)


def test_github_app_token_detected():
    hits = _scan("token=ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
    assert any(h.rule_id == "github-app" for h in hits)


def test_google_api_key_detected():
    hits = _scan("key AIzaSyD-9tSrke72PouQMnMXr7wZ3pK1MfTQw7oX end")
    assert any(h.rule_id == "google-api-key" for h in hits)


def test_google_oauth_detected():
    hits = _scan("Authorization: Bearer ya29.a0ARrdaM-abcdefghijklmnopqrstuvwxyz")
    assert any(h.rule_id == "google-oauth" for h in hits)


def test_slack_token_detected():
    hits = _scan("slack xoxb-1234567890-abcdefghij")
    assert any(h.rule_id == "slack-token" for h in hits)


def test_slack_webhook_detected():
    hits = _scan("https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX")
    assert any(h.rule_id == "slack-webhook" for h in hits)


def test_stripe_secret_key_detected():
    hits = _scan("STRIPE_KEY=sk_live_abcdef1234567890abcdef123456")
    assert any(h.rule_id == "stripe-secret-key" for h in hits)


def test_stripe_restricted_key_detected():
    hits = _scan("STRIPE_KEY=rk_live_abcdef1234567890abcdef123456")
    assert any(h.rule_id == "stripe-restricted-key" for h in hits)


def test_private_key_block_detected():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1234567890\n"
        "-----END RSA PRIVATE KEY-----"
    )
    hits = _scan(pem)
    assert any(h.rule_id == "private-key-block" for h in hits)
    assert hits[0].severity == Severity.CRITICAL


def test_openssh_private_key_detected():
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    hits = _scan(pem)
    assert any(h.rule_id == "private-key-block" for h in hits)


def test_jwt_detected():
    hits = _scan("Authorization: Bearer eyJabcdefgh.eyJabcdefgh.SflKxw12")
    assert any(h.rule_id == "jwt" for h in hits)


def test_jwt_too_short_rejected():
    # Only 4 chars between dots -> should not match (needs 8+)
    hits = _scan("abc.eyJx.def")
    assert not any(h.rule_id == "jwt" for h in hits)


def test_generic_api_key_in_env_format():
    hits = _scan('api_key = "abcdefghijklmnop123456"')
    assert any(h.rule_id == "generic-api-key" for h in hits)


def test_generic_api_key_placeholder_rejected():
    hits = _scan('api_key = "your_api_key_here"')
    assert not any(h.rule_id == "generic-api-key" for h in hits)


def test_bearer_token_detected():
    hits = _scan("Authorization: Bearer abcdefghij1234567890abcdefghij")
    assert any(h.rule_id == "bearer-token" for h in hits)


def test_connection_string_detected():
    hits = _scan("DATABASE_URL=postgres://admin:hunter2@db.internal:5432/prod")
    assert any(h.rule_id == "connection-string" for h in hits)


def test_connection_string_placeholder_rejected():
    hits = _scan("postgres://user:pass@host:5432/db")
    assert not any(h.rule_id == "connection-string" for h in hits)


def test_email_detected():
    hits = _scan("contact me at john.doe@acme.io please")
    assert any(h.rule_id == "email" for h in hits)


def test_email_example_domain_rejected():
    hits = _scan("from noreply@example.com to user@test.com")
    # Both should be filtered by allowlist
    assert not any(h.rule_id == "email" for h in hits)


def test_us_ssn_detected():
    hits = _scan("my ssn is 123-45-6789")
    assert any(h.rule_id == "us-ssn" for h in hits)


def test_us_ssn_invalid_rejected():
    # 000 series rejected
    hits = _scan("ssn 000-12-3456")
    assert not any(h.rule_id == "us-ssn" for h in hits)


def test_iban_detected():
    hits = _scan("iban GB82WEST12345698765432")
    assert any(h.rule_id == "iban" for h in hits)


def test_credit_card_visa_detected():
    hits = _scan("card 4111111111111111")
    assert any(h.rule_id == "credit-card" for h in hits)


def test_credit_card_invalid_rejected():
    # 16 digits but Luhn fails
    hits = _scan("card 1234567890123456")
    assert not any(h.rule_id == "credit-card" for h in hits)


def test_us_phone_detected():
    hits = _scan("call (555) 123-4567")
    assert any(h.rule_id == "us-phone" for h in hits)


def test_clean_text_no_findings():
    hits = _scan("hello world, this is a normal message with no secrets")
    assert hits == []


def test_finding_has_rotation_guide_for_critical():
    hits = _scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE2")
    assert hits[0].rotation_guide is not None
    assert "IAM" in hits[0].rotation_guide


def test_finding_has_context_window():
    text = "prefix text AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE2 suffix text"
    hits = _scan(text)
    assert hits
    f = hits[0]
    assert f.span_start < f.span_end
    assert "AWS_ACCESS_KEY_ID" in f.context
