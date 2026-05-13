from vuln_commit_kg.config import ModelConfig
from vuln_commit_kg.models.openai_compatible import OpenAICompatibleModel


def test_api_disable_thinking_injects_chat_template_kwargs():
    cfg = ModelConfig(
        backend="openai_compatible",
        model_name="qwen3.5-397b-a17b",
        api_base="https://chat-ai.academiccloud.de/v1",
        api_disable_thinking=True,
        api_extra_body={},
    )
    model = OpenAICompatibleModel(cfg)
    payload = model._payload("Return exactly: OK", "system")
    assert payload["chat_template_kwargs"]["enable_thinking"] is False
    assert "/no_think" not in payload["messages"][1]["content"]


def test_api_extra_body_nested_merge_preserves_disable_thinking():
    cfg = ModelConfig(
        backend="openai_compatible",
        model_name="qwen3.5-397b-a17b",
        api_base="https://chat-ai.academiccloud.de/v1",
        api_disable_thinking=True,
        api_extra_body={"chat_template_kwargs": {"some_other_flag": "x"}, "extra_top_level": 1},
    )
    model = OpenAICompatibleModel(cfg)
    payload = model._payload("Return exactly: OK", "system")
    assert payload["chat_template_kwargs"]["enable_thinking"] is False
    assert payload["chat_template_kwargs"]["some_other_flag"] == "x"
    assert payload["extra_top_level"] == 1
