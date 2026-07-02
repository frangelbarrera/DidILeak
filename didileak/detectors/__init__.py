"""Detector engine: regex + gitleaks-style rules with context checks."""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass

from didileak.models import Finding, Message, Severity


def _mask(value: str, keep: int = 4) -> str:
    """Mask a secret for safe display: `ghp_abc...wxyz` -> `ghp_...wxyz`."""
    if len(value) < keep * 2:
        return value[:1] + "*" * (len(value) - 2) + value[-1:] if len(value) > 2 else "***"
    return value[:keep] + "..." + value[-keep:]


def _fingerprint(value: str) -> str:
    """Stable hash so the same secret leaked across many messages counts once."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass
class Rule:
    """A single detection rule (gitleaks-style)."""

    rule_id: str
    name: str
    category: str  # "secret" | "pii" | "key"
    severity: Severity
    pattern: re.Pattern
    # Optional second-pass filter on the matched value (e.g. Luhn, character set)
    validator: callable | None = None
    # Optional context check: only fire if any keyword appears within N chars
    context_keywords: list[str] | None = None
    context_radius: int = 60
    # Allowlist of substrings that suppress a match (false-positive guards)
    allowlist: list[str] | None = None
    rotation_guide: str | None = None


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #

def _luhn_valid(card_number: str) -> bool:
    """Luhn checksum used by all major credit cards."""
    digits = [int(c) for c in re.sub(r"\D", "", card_number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _aws_access_key_valid(value: str) -> bool:
    """AKIA + 16 base32-ish chars; reject obvious placeholders."""
    if len(value) != 20:
        return False
    return not re.search(r"(AKIA0000|AKIATEST|AKIAEXAMPLE|AKIAFAKE)", value, re.I)


def _github_token_valid(value: str) -> bool:
    # GitHub PATs: prefix + 36+ chars in [A-Za-z0-9]
    # Reject obvious placeholders (case-insensitive, on word boundaries)
    return not re.search(r"\b(EXAMPLE|FAKE|PLACEHOLDER|YOUR_TOKEN|XXXX)\b", value, re.I)


def _is_uuid_like(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F-]{36}", value))


# --------------------------------------------------------------------------- #
# Rule definitions — inspired by gitleaks v8 config
# --------------------------------------------------------------------------- #

RULES: list[Rule] = [
    # ---- Cloud provider keys --------------------------------------------- #
    Rule(
        rule_id="aws-access-token",
        name="AWS Access Key",
        category="key",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        validator=_aws_access_key_valid,
        rotation_guide=(
            "Rotate now: AWS Console -> IAM -> Users -> your user -> "
            "Security credentials -> Create access key. Delete the old key. "
            "Audit CloudTrail for unauthorized API calls in the last 90 days."
        ),
    ),
    Rule(
        rule_id="aws-secret-access-key",
        name="AWS Secret Access Key (with context)",
        category="secret",
        severity=Severity.CRITICAL,
        # Loose pattern; only fires when AWS context is nearby
        pattern=re.compile(r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])"),
        context_keywords=["aws_secret_access_key", "aws secret", "AKIA", "aws_session_token"],
        context_radius=80,
        rotation_guide=(
            "Treat as compromised. Rotate the IAM access key pair, audit "
            "CloudTrail, and check for new IAM users or roles you did not create."
        ),
    ),

    # ---- GitHub tokens --------------------------------------------------- #
    Rule(
        rule_id="github-pat",
        name="GitHub Personal Access Token (classic)",
        category="secret",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"ghp_[A-Za-z0-9]{36,}"),
        validator=_github_token_valid,
        rotation_guide=(
            "Revoke immediately: https://github.com/settings/tokens -> find the "
            "token -> Delete. Create a new fine-grained PAT with minimal scope. "
            "Check your repos' audit log and Security tab for unauthorized pushes."
        ),
    ),
    Rule(
        rule_id="github-oauth",
        name="GitHub OAuth Token",
        category="secret",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"gho_[A-Za-z0-9]{36,}"),
        validator=_github_token_valid,
        rotation_guide=(
            "Revoke: https://github.com/settings/applications -> find the OAuth "
            "app -> Revoke. Re-authorize only if you still use it."
        ),
    ),
    Rule(
        rule_id="github-app",
        name="GitHub App / User-to-Server Token",
        category="secret",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"(ghu|ghs|ghr)_[A-Za-z0-9]{36,}"),
        validator=_github_token_valid,
        rotation_guide=(
            "Revoke at the GitHub App settings page or via the API. "
            "Rotate the App's private key if you suspect the App itself was leaked."
        ),
    ),

    # ---- Google / GCP ---------------------------------------------------- #
    Rule(
        rule_id="google-api-key",
        name="Google API Key",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
        rotation_guide=(
            "Restrict + rotate: https://console.cloud.google.com/apis/credentials "
            "-> find the key -> restrict to specific APIs and referrers, then "
            "create a replacement and delete the leaked one."
        ),
    ),
    Rule(
        rule_id="google-oauth",
        name="Google OAuth Access Token",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"ya29\.[0-9A-Za-z_\-]+"),
        rotation_guide=(
            "OAuth access tokens expire (~1h) but revoke to be safe: "
            "https://myaccount.google.com/permissions. Re-issue refresh tokens."
        ),
    ),

    # ---- Slack ----------------------------------------------------------- #
    Rule(
        rule_id="slack-token",
        name="Slack Token",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
        rotation_guide=(
            "Rotate: https://api.slack.com/rotating-and-invalidating-credentials. "
            "Revoke the token, generate a new one, and check Slack access logs."
        ),
    ),
    Rule(
        rule_id="slack-webhook",
        name="Slack Webhook URL",
        category="secret",
        severity=Severity.MEDIUM,
        pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        rotation_guide=(
            "Recreate the webhook: Slack app -> Incoming Webhooks -> delete the old "
            "URL and create a new one. Update all callers."
        ),
    ),

    # ---- Stripe ---------------------------------------------------------- #
    Rule(
        rule_id="stripe-secret-key",
        name="Stripe Live Secret Key",
        category="secret",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        rotation_guide=(
            "Roll the key IMMEDIATELY: https://dashboard.stripe.com/apikeys -> "
            "Roll... on the leaked key. Update your backend. Review Stripe logs "
            "for fraud or unexpected charges."
        ),
    ),
    Rule(
        rule_id="stripe-restricted-key",
        name="Stripe Live Restricted Key",
        category="secret",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"rk_live_[0-9a-zA-Z]{24,}"),
        rotation_guide="Same as sk_live — roll at https://dashboard.stripe.com/apikeys.",
    ),

    # ---- Private keys ---------------------------------------------------- #
    Rule(
        rule_id="private-key-block",
        name="Private Key (PEM block)",
        category="key",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
            r"[\s\S]{1,4000}?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
        ),
        rotation_guide=(
            "Treat the key as fully compromised. Revoke everywhere it was authorized "
            "(GitHub deploy keys, server authorized_keys, etc.), generate a new pair, "
            "and rotate any access it granted."
        ),
    ),

    # ---- JWTs ------------------------------------------------------------ #
    Rule(
        rule_id="jwt",
        name="JSON Web Token",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        rotation_guide=(
            "JWTs are short-lived but may leak claims (PII, scopes). Revoke the "
            "session server-side if possible, and rotate the signing key if you "
            "suspect the JWT was forged."
        ),
    ),

    # ---- Generic env-style secrets --------------------------------------- #
    Rule(
        rule_id="generic-api-key",
        name="Generic API Key in env-style assignment",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|private[_-]?key|passwd|password)\b\s*[:=]\s*"
            r"['\"]?[A-Za-z0-9_\-]{16,}['\"]?"
        ),
        allowlist=["example", "placeholder", "your_", "xxxx", "changeme", "<", ">"],
        rotation_guide=(
            "Identify the system this credential belongs to (look at the variable "
            "name and surrounding text) and rotate it on that provider's dashboard."
        ),
    ),
    Rule(
        rule_id="bearer-token",
        name="Authorization Bearer Token",
        category="secret",
        severity=Severity.HIGH,
        pattern=re.compile(r"(?i)\bBearer\s+[A-Za-z0-9_\-\.=]{20,}"),
        rotation_guide=(
            "Rotate the underlying token on the API provider's dashboard. "
            "Audit API logs for abuse."
        ),
    ),
    Rule(
        rule_id="connection-string",
        name="Database Connection String",
        category="secret",
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"(?:postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|amqps)://"
            r"[^\s\"'<>]+:[^\s\"'<>@]+@[^\s\"'<>]+"
        ),
        allowlist=["example", "user:pass@", "username:password@"],
        rotation_guide=(
            "Rotate the DB password immediately, restrict the user's IP allowlist, "
            "and audit query logs for data exfiltration."
        ),
    ),

    # ---- PII ------------------------------------------------------------- #
    Rule(
        rule_id="email",
        name="Email address",
        category="pii",
        severity=Severity.LOW,
        pattern=re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"),
        allowlist=["@example.com", "@example.org", "@example.net", "@test.com", "@your-domain.com", "@domain.com", "noreply@", "no-reply@", "sentry@"],
        rotation_guide=None,
    ),
    Rule(
        rule_id="us-phone",
        name="US phone number",
        category="pii",
        severity=Severity.INFO,
        pattern=re.compile(r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
        rotation_guide=None,
    ),
    Rule(
        rule_id="us-ssn",
        name="US Social Security Number",
        category="pii",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        rotation_guide=(
            "SSN exposure is severe. Place a fraud alert or freeze with the three "
            "US credit bureaus (Equifax, Experian, TransUnion). File IRS Form 14039 "
            "if you suspect tax fraud."
        ),
    ),
    Rule(
        rule_id="iban",
        name="IBAN (international bank account)",
        category="pii",
        severity=Severity.HIGH,
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        rotation_guide=(
            "Notify your bank. They can monitor or reissue the account number. "
            "Freeze the account if you see unauthorized transactions."
        ),
    ),
    Rule(
        rule_id="credit-card",
        name="Credit Card Number",
        category="pii",
        severity=Severity.CRITICAL,
        pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        validator=_luhn_valid,
        rotation_guide=(
            "Report the card as compromised to your bank IMMEDIATELY. They will "
            "issue a new number and you will not be liable for fraud."
        ),
    ),
]


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #

class DetectorEngine:
    """Run all rules over a sequence of messages."""

    def __init__(self, rules: Iterable[Rule] | None = None):
        self.rules = list(rules) if rules is not None else RULES

    def scan_message(self, msg: Message) -> list[Finding]:
        findings: list[Finding] = []
        text = msg.content or ""
        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                value = match.group(0)
                if rule.allowlist and any(
                    a.lower() in value.lower() for a in rule.allowlist
                ):
                    continue
                if rule.validator and not rule.validator(value):
                    continue
                if rule.context_keywords:
                    window = text[max(0, match.start() - rule.context_radius):
                                  match.end() + rule.context_radius].lower()
                    if not any(kw.lower() in window for kw in rule.context_keywords):
                        continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        provider=msg.provider,
                        conversation_id=msg.conversation_id,
                        conversation_title=msg.conversation_title,
                        message_id=msg.message_id,
                        message_index=msg.index,
                        role=msg.role,
                        timestamp=msg.timestamp,
                        matched_value=value,
                        masked_value=_mask(value),
                        span_start=match.start(),
                        span_end=match.end(),
                        context=msg.context(match.start(), match.end()),
                        rotation_guide=rule.rotation_guide,
                    )
                )
        return findings

    def scan(self, messages: Iterable[Message]) -> list[Finding]:
        out: list[Finding] = []
        for m in messages:
            out.extend(self.scan_message(m))
        return out
