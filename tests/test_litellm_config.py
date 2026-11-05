import json
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

DEPLOY = Path(__file__).resolve().parent.parent / "deploy" / "litellm"

ALLOWLIST = {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "KR_RRN", "KR_STUDENT_ID"}
FORBIDDEN = {"LOCATION", "PERSON", "DATE_TIME", "NRP", "URL"}


def _load_config():
    return yaml.safe_load((DEPLOY / "config.yaml").read_text(encoding="utf-8"))


def _presidio_params(config):
    guardrails = config.get("guardrails") or []
    guard = [g for g in guardrails if g.get("guardrail_name") == "presidio-pii"]
    assert len(guard) == 1
    params = guard[0].get("litellm_params")
    assert isinstance(params, dict)
    return params


def test_presidio_guardrail_present_and_scoped_to_input():
    config = _load_config()
    params = _presidio_params(config)
    assert params.get("guardrail") == "presidio"
    assert params.get("mode") == "pre_call"
    assert params.get("default_on") is True
    assert params.get("presidio_filter_scope") == "input"
    assert params.get("presidio_ad_hoc_recognizers") == "/app/ko_recognizers.json"
    assert params.get("output_parse_pii") is True
    assert "database_url" not in (config.get("litellm_settings") or {})


def test_pii_entities_config_is_exact_allowlist_and_all_mask():
    config = _load_config()
    entities = _presidio_params(config).get("pii_entities_config") or {}
    assert set(entities) == ALLOWLIST
    assert all(action == "MASK" for action in entities.values())
    assert not (set(entities) & FORBIDDEN)


def test_no_literal_secrets_in_config():
    text = (DEPLOY / "config.yaml").read_text(encoding="utf-8")
    assert "sk-" not in text
    assert not re.search(r"(?i)(api[_-]?key|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}", text)
    assert "os.environ/" in text


def test_ko_recognizers_valid_and_entities_in_allowlist():
    recognizers = json.loads((DEPLOY / "ko_recognizers.json").read_text(encoding="utf-8"))
    assert recognizers, "recognizer list must not be empty"
    for rec in recognizers:
        assert rec["supported_entity"] in ALLOWLIST
        assert rec["patterns"], f"{rec['name']} must define at least one pattern"
