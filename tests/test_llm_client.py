# Model selection per role (chat=fast model, analysis/rewrite=fallback to LLM_MODEL)
from zp_release_guard import llm_client


def test_role_model_selection(monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "deepseek/deepseek-v4-pro")
    monkeypatch.setenv("LLM_MODEL_CHAT", "google/gemma-4-31b-it")
    monkeypatch.delenv("LLM_MODEL_ANALYSIS", raising=False)
    monkeypatch.delenv("LLM_MODEL_REWRITE", raising=False)

    assert llm_client.model_for("chat") == "google/gemma-4-31b-it"   # fast model
    assert llm_client.model_for("analysis") == "deepseek/deepseek-v4-pro"  # fallback → deep
    assert llm_client.model_for("rewrite") == "deepseek/deepseek-v4-pro"   # fallback
    # 'analysis' role is registered
    assert "analysis" in llm_client._ROLE_ENV


def test_unconfigured_returns_none(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    assert llm_client.is_configured() is False
    assert llm_client.chat_completion([{"role": "user", "content": "hi"}]) is None
