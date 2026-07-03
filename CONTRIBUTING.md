# Contributing to DidILeak

First of all: **thank you for considering contributing.** DidILeak is a community-driven security tool, and every detector, parser, or fix you add makes the LLM ecosystem a little safer for everyone.

This document is intentionally short. You don't need permission, you don't need to be a security expert, and you don't need to write perfect code. If you found a secret pattern DidILeak should catch, you can contribute.

## The 30-second version

```bash
git clone https://github.com/frangelbarrera/DidILeak.git
cd DidILeak
pip install -e ".[dev]"

# make your change

pytest              # 170 tests, 90%+ coverage required
ruff check didileak tests   # must be clean

git checkout -b my-feature
git commit -m "feat: add detector for X"
git push origin my-feature
# open a PR
```

That's it. No CLA, no signing, no ceremony.

## Ways to contribute

You don't have to write code. These are all valuable:

| Way | How |
|---|---|
| **Report a false positive** | Open an issue with the matched text (masked), the rule ID, and what you expected |
| **Report a false negative** | Paste a snippet that should have been detected but wasn't (redact real secrets first!) |
| **Add a detector** | One `Rule(...)` entry in `didileak/detectors/__init__.py` — see below |
| **Improve a parser** | Better handling of edge cases in `didileak/parsers/` |
| **Improve docs** | Fix typos, clarify sections, add examples |
| **Share rotation guides** | If you've rotated a specific secret type and have a better guide, update it |
| **Test on real exports** | Run DidILeak on your own ChatGPT/Claude/Cursor export and report what breaks |

## Adding a new detector (most common contribution)

Detectors live in [`didileak/detectors/__init__.py`](didileak/detectors/__init__.py). Each detector is a `Rule` object:

```python
Rule(
    rule_id="huggingface-token",              # unique, kebab-case
    name="Hugging Face Access Token",          # human-readable
    category="secret",                         # "secret" | "key" | "pii"
    severity=Severity.HIGH,                    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    pattern=re.compile(r"hf_[A-Za-z0-9]{30,}"),
    validator=None,                            # optional: callable that returns bool
    context_keywords=None,                     # optional: list[str], only fire if any nearby
    allowlist=["hf_example", "hf_your_token"], # optional: substrings that suppress a match
    rotation_guide="Rotate at https://huggingface.co/settings/tokens",
),
```

### Choosing a severity

| Severity | Use for | Example |
|---|---|---|
| **CRITICAL** | Allows immediate account takeover or financial fraud | AWS keys, GitHub PATs, Stripe live keys, private SSH keys, SSNs |
| **HIGH** | Allows unauthorized access but limited blast radius | Slack tokens, Google API keys, JWTs, DB connection strings |
| **MEDIUM** | Webhook URLs, internal tokens with limited scope | Slack webhooks |
| **LOW** | PII that's identifying but not directly exploitable | Email addresses |
| **INFO** | Contextual info, not a secret per se | US phone numbers |

### Writing a good rotation guide

A good rotation guide tells the user **exactly** what to do, in order:

> Revoke immediately: https://github.com/settings/tokens → find the token → Delete. Create a new fine-grained PAT with minimal scope. Check your repos' audit log and Security tab for unauthorized pushes.

Three things it should include:
1. **Where to go** (URL or navigation path)
2. **What to do there** (delete, rotate, regenerate)
3. **What to check after** (audit logs, unauthorized access)

### Testing your detector

Add a test in [`tests/test_detectors.py`](tests/test_detectors.py):

```python
def test_huggingface_token_detected():
    hits = _scan("HF_TOKEN=hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890")
    assert any(h.rule_id == "huggingface-token" for h in hits)
```

Run:

```bash
pytest tests/test_detectors.py -v
```

## Adding a parser

If you want to support a new LLM provider's export format:

1. Create `didileak/parsers/yourprovider.py`
2. Implement a class that inherits from `Parser` and yields `Message` objects
3. Register it in `didileak/parsers/__init__.py` (both `detect_provider` and `get_parser`)
4. Add tests in `tests/test_parsers.py`

Look at [`didileak/parsers/chatgpt.py`](didileak/parsers/chatgpt.py) for a complete example.

## Code style

- **Python 3.9+** — use `from __future__ import annotations` if you write `X | None` type hints
- **Line length:** 100 chars (configured in `pyproject.toml`)
- **Linter:** `ruff` — just run `ruff check didileak tests` and fix any errors
- **Tests:** required for new code. Coverage must stay above 90%.
- **No new dependencies** without discussion in an issue first. DidILeak should stay lightweight.

## Commit message conventions

We use [Conventional Commits](https://www.conventionalcommits.org/) but we're not religious about it:

```
feat: add Hugging Face token detector
fix: false positive on example.com emails
docs: clarify rotation guide for AWS keys
test: add edge cases for credit card validator
chore: bump coverage threshold to 90%
```

The important thing: **explain why**, not just what. A good commit message:

```
fix: reject AWS keys with EXAMPLE placeholder

The _aws_access_key_valid validator was not rejecting tokens like
AKIAEXAMPLE00000000 because the regex only matched AKIA0000 and
AKIATEST. Added AKIAEXAMPLE and AKIAFAKE to the rejection list.

Fixes #42
```

## Pull requests

1. **Branch from `main`** — `git checkout -b my-feature`
2. **One PR per feature** — don't bundle unrelated changes
3. **Keep it small** — under 500 lines if possible. Big PRs take longer to review.
4. **Tests must pass** — `pytest` and `ruff check` must be clean
5. **Coverage must stay ≥90%** — CI will fail if it drops below

You don't need to squash your commits. We squash on merge.

## Reporting security issues

**Do NOT open a public issue for security vulnerabilities in DidILeak itself.**

If you find a way DidILeak could leak data, bypass masking, or otherwise fail its security purpose, email the maintainer directly (see GitHub profile). Use a descriptive subject line like `DidILeak security: <brief description>`.

If you found a real leaked secret in your own scan and need help with incident response, that's not a DidILeak bug — follow the rotation guide DidILeak gave you.

## Getting help

- **Questions?** Open a [Discussion](https://github.com/frangelbarrera/DidILeak/discussions) (if enabled) or an issue with the `question` label.
- **Stuck?** Comment on the relevant issue or open a new one. We're friendly.
- **Imposter syndrome?** Pull requests from first-time contributors are especially welcome. We will help you through the review process.

## Recognition

All contributors are added to the README's contributor list (coming soon). Significant contributions (new parsers, major detector additions) get a shoutout in the CHANGELOG.

---

**One last thing:** DidILeak exists because the LLM ecosystem has a real security problem. Every detector you add, every false positive you report, every parser you improve — it makes the next person who pastes a secret into ChatGPT a little safer. That's the whole point.
