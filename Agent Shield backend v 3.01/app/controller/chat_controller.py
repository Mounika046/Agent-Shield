from typing import Any, Callable, Dict, Optional

try:
    from app.agents.unified_scan_agent import run_unified_scan
    from app.controller.formatter import (
        build_dependencies_discovered_table,
        build_dependency_graphs,
        build_fix_analysis,
        build_license_sources,
        build_license_compliance_table,
        build_response_meta,
        build_summary_cards,
        build_vulnerable_dependencies_table,
        format_chat_response,
    )
    from app.controller.interpreter import normalize_github_repo_url
    from app.controller.llm import AgentLLM, get_default_llm_with_status
    from app.controller.llm_input import run_input_llm_stage
    from app.controller.llm_output import run_output_llm_stage
    from app.controller.prompts import load_agent_prompt
    from app.schemas import PackageCoordinate
except ModuleNotFoundError:
    from agents.unified_scan_agent import run_unified_scan
    from controller.formatter import (
        build_dependencies_discovered_table,
        build_dependency_graphs,
        build_fix_analysis,
        build_license_sources,
        build_license_compliance_table,
        build_response_meta,
        build_summary_cards,
        build_vulnerable_dependencies_table,
        format_chat_response,
    )
    from controller.interpreter import normalize_github_repo_url
    from controller.llm import AgentLLM, get_default_llm_with_status
    from controller.llm_input import run_input_llm_stage
    from controller.llm_output import run_output_llm_stage
    from controller.prompts import load_agent_prompt
    from schemas import PackageCoordinate


ScanExecutor = Callable[..., Dict[str, Any]]
REDACTED = "***redacted***"
SENSITIVE_KEYS = {"token", "authorization", "access_token", "api_key", "secret", "password"}


def _mode_for_clarification(mode: Optional[str], mode_source: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if mode and mode_source == "explicit":
        return mode, mode_source
    return None, None


def _build_clarification_response(
    *,
    message: str,
    input_type: str,
    mode: Optional[str],
    mode_source: Optional[str],
    prompt_loaded: bool,
    llm_input_stage: bool,
    llm_diagnostics: Dict[str, Any],
    validation_error: Optional[str] = None,
) -> Dict[str, Any]:
    resolved_mode, resolved_mode_source = _mode_for_clarification(mode, mode_source)
    response_meta = {
        "needs_backend_input": True,
        "llm_input_stage": llm_input_stage,
        "llm_output_stage": False,
        "llm_available": llm_diagnostics.get("llm_available", llm_input_stage),
        "llm_fallback_reason": llm_diagnostics.get("llm_fallback_reason"),
        "llm_diagnostics": llm_diagnostics,
        "clarification_builder": "shared",
    }
    if validation_error:
        response_meta["validation_error"] = validation_error
    return {
        "status": "needs_clarification",
        "message": message,
        "backend_called": False,
        "backend_payload": None,
        "mode": resolved_mode,
        "mode_source": resolved_mode_source,
        "input_type": input_type,
        "controller_prompt_loaded": prompt_loaded,
        "response_meta": response_meta,
    }


def _sanitize_for_response(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, item in value.items():
            if str(key).strip().lower() in SENSITIVE_KEYS:
                sanitized[key] = REDACTED if item else None
            else:
                sanitized[key] = _sanitize_for_response(item)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_for_response(item) for item in value]
    return value


def _payload_input_type(payload: Dict[str, Any]) -> str:
    if payload.get("repo_url"):
        return "github_repo"
    if payload.get("file_name") or payload.get("file_content") is not None:
        return "dependency_file"
    if payload.get("packages") or payload.get("package_name") or payload.get("package_version"):
        return "package"
    return "unknown"


def handle_chat_request(
    *,
    message: str,
    repo_url: Optional[str] = None,
    token: Optional[str] = None,
    packages: Optional[list[PackageCoordinate]] = None,
    package_name: Optional[str] = None,
    package_version: Optional[str] = None,
    ecosystem: Optional[str] = None,
    file_name: Optional[str] = None,
    file_content: Optional[str] = None,
    mode: Optional[str] = None,
    include_debug: bool = False,
    scan_executor: ScanExecutor = run_unified_scan,
    input_llm_client: Optional[AgentLLM] = None,
    output_llm_client: Optional[AgentLLM] = None,
) -> Dict[str, Any]:
    prompt_loaded = bool(load_agent_prompt())
    llm_diagnostics: Dict[str, Any] = {}
    default_llm = None
    normalized_repo_url = normalize_github_repo_url(repo_url)
    if input_llm_client is None and output_llm_client is None:
        default_llm, llm_diagnostics = get_default_llm_with_status()
    else:
        llm_diagnostics = {
            "llm_available": True,
            "llm_fallback_reason": None,
            "injected_llm_client": True,
        }
    input_client = input_llm_client or default_llm
    output_client = output_llm_client or default_llm
    structured_fields = {
        "repo_url": normalized_repo_url,
        "token": token,
        "packages": [item.model_dump() if hasattr(item, "model_dump") else item for item in (packages or [])],
        "package_name": package_name,
        "package_version": package_version,
        "ecosystem": ecosystem,
        "file_name": file_name,
        "file_content": file_content,
        "mode": mode,
    }
    try:
        decision = run_input_llm_stage(
            message=message,
            structured_fields=structured_fields,
            llm_client=input_client,
        )
    except ValueError as exc:
        return _build_clarification_response(
            message="I need one more detail before I can run this safely. Could you provide the missing or ambiguous scan target information?",
            input_type="unknown",
            mode=mode,
            mode_source="explicit" if mode else None,
            prompt_loaded=prompt_loaded,
            llm_input_stage=input_client is not None,
            llm_diagnostics=llm_diagnostics,
            validation_error=str(exc),
        )
    payload = decision.get("backend_payload", {})
    if payload.get("repo_url"):
        payload["repo_url"] = normalize_github_repo_url(payload.get("repo_url"))

    if decision.get("action") == "clarify":
        return _build_clarification_response(
            message=decision.get("question", "Could you clarify what you want analyzed?"),
            input_type=decision.get("input_type", "unknown"),
            mode=decision.get("mode"),
            mode_source=decision.get("mode_source"),
            prompt_loaded=prompt_loaded,
            llm_input_stage=input_client is not None,
            llm_diagnostics=llm_diagnostics,
        )

    result = scan_executor(**payload)
    answer = run_output_llm_stage(
        message=message,
        mode=payload.get("mode") or "fast",
        backend_result=result,
        llm_client=output_client,
    )
    response_meta = build_response_meta(result)
    response_meta["llm_input_stage"] = input_client is not None
    response_meta["llm_output_stage"] = output_client is not None
    response_meta["llm_available"] = llm_diagnostics.get("llm_available", input_client is not None)
    response_meta["llm_fallback_reason"] = llm_diagnostics.get("llm_fallback_reason")
    response_meta["llm_diagnostics"] = llm_diagnostics
    response = {
        "status": "completed",
        "message": answer,
        "llm_response": answer,
        "backend_called": True,
        "backend_payload": _sanitize_for_response(payload),
        "mode": payload.get("mode"),
        "mode_source": decision.get("mode_source", "inferred"),
        "input_type": _payload_input_type(payload),
        "response_type": "scan_result",
        "cards": build_summary_cards(result),
        "dependencies_discovered_table": build_dependencies_discovered_table(result),
        "vulnerable_dependencies_table": build_vulnerable_dependencies_table(result),
        "license_compliance_table": build_license_compliance_table(result, payload.get("mode")),
        "dependency_graphs": build_dependency_graphs(result, payload.get("mode")),
        "fix_analysis": build_fix_analysis(result, payload.get("mode")),
        "license_sources": build_license_sources(result, payload.get("mode")),
        "controller_prompt_loaded": prompt_loaded,
        "response_meta": response_meta,
    }
    if include_debug:
        response["scan_result"] = _sanitize_for_response(result)
    return response
