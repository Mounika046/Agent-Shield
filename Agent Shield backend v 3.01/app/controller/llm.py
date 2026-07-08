import json
from pathlib import Path
from typing import Any, Dict, Optional, Protocol, Tuple

try:
    from app.config import get_config
except ModuleNotFoundError:
    from config import get_config

try:
    from oci_openai import OciOpenAI, OciUserPrincipalAuth
except Exception:
    OciOpenAI = None
    OciUserPrincipalAuth = None


class AgentLLM(Protocol):
    def complete(self, *, system_prompt: str, user_payload: Dict[str, Any]) -> str:
        ...


class OciAgentLLM:
    def __init__(self):
        settings = get_config()
        if OciOpenAI is None or OciUserPrincipalAuth is None:
            raise RuntimeError("oci_openai package is not available.")
        if not settings.oci_config_file or not settings.oci_compartment_id:
            raise RuntimeError("OCI LLM config is not set.")
        config_path = Path(settings.oci_config_file)
        if not config_path.is_file():
            raise RuntimeError("OCI_CONFIG_FILE must point to the OCI config file, not a directory.")
        self.model_id = settings.oci_model_id
        self.client = OciOpenAI(
            region=settings.oci_region,
            auth=OciUserPrincipalAuth(
                config_file=settings.oci_config_file,
                profile_name=settings.oci_config_profile,
            ),
            compartment_id=settings.oci_compartment_id,
        )

    def complete(self, *, system_prompt: str, user_payload: Dict[str, Any]) -> str:
        response = self.client.responses.create(
            model=self.model_id,
            store=False,
            input=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
        )
        return str(getattr(response, "output_text", "") or "").strip()


def get_llm_diagnostics() -> Dict[str, Any]:
    settings = get_config()
    config_path = settings.oci_config_file
    path_exists = bool(config_path and Path(config_path).exists())
    path_is_file = bool(config_path and Path(config_path).is_file())
    path_readable = False
    if path_is_file:
        try:
            with open(config_path, "r", encoding="utf-8"):
                path_readable = True
        except OSError:
            path_readable = False
    return {
        "env_file_loaded": settings.env_file_loaded,
        "env_file_path": settings.env_file_path,
        "oci_openai_imported": OciOpenAI is not None and OciUserPrincipalAuth is not None,
        "has_oci_config_file": bool(config_path),
        "oci_config_file_exists": path_exists,
        "oci_config_file_is_file": path_is_file,
        "oci_config_file_readable": path_readable,
        "has_oci_compartment_id": bool(settings.oci_compartment_id),
        "has_oci_region": bool(settings.oci_region),
        "has_oci_model_id": bool(settings.oci_model_id),
        "has_oci_config_profile": bool(settings.oci_config_profile),
        "oci_region": settings.oci_region,
        "oci_model_id": settings.oci_model_id,
        "oci_config_profile": settings.oci_config_profile,
        "require_agent_llm": settings.require_agent_llm,
    }


def _sanitize_error(message: str) -> str:
    settings = get_config()
    sanitized = message
    if settings.oci_config_file:
        sanitized = sanitized.replace(settings.oci_config_file, "<OCI_CONFIG_FILE>")
    return sanitized


def get_default_llm_with_status() -> Tuple[Optional[AgentLLM], Dict[str, Any]]:
    diagnostics = get_llm_diagnostics()
    try:
        llm = OciAgentLLM()
        diagnostics["llm_available"] = True
        diagnostics["llm_fallback_reason"] = None
        return llm, diagnostics
    except Exception as exc:
        diagnostics["llm_available"] = False
        diagnostics["llm_fallback_reason"] = _sanitize_error(f"{type(exc).__name__}: {exc}")
        if get_config().require_agent_llm:
            raise RuntimeError(diagnostics["llm_fallback_reason"]) from exc
        return None, diagnostics


def get_default_llm() -> Optional[AgentLLM]:
    llm, _diagnostics = get_default_llm_with_status()
    return llm
