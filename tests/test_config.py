from agent.config import OpenAIConfig, RetryPolicy, DEFAULT_RETRY_POLICY


def test_retry_policy_defaults():
    p = RetryPolicy()
    assert p.max_attempts == 3
    assert p.base_delay == 0.1
    assert p.max_delay == 2.0


def test_default_retry_policy_singleton():
    assert DEFAULT_RETRY_POLICY.max_attempts == 3


def test_openai_config_reads_env(monkeypatch):
    monkeypatch.setenv("OPENAI_API_BASE", "https://example.test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_MODEL_NAME", "gpt-test")
    monkeypatch.setenv("OPENAI_TEMPERATURE", "0.25")
    monkeypatch.setenv("OPENAI_MODEL_SEED", "12345")
    cfg = OpenAIConfig.from_env()
    assert cfg.api_base == "https://example.test"
    assert cfg.api_key == "sk-test"
    assert cfg.model_name == "gpt-test"
    assert cfg.temperature == 0.25
    assert isinstance(cfg.temperature, float)
    assert cfg.model_seed == 12345
    assert isinstance(cfg.model_seed, int)
