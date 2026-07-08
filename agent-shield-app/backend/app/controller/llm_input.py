import json
from typing import Any, Dict, Optional

try:
    from app.controller.interpreter import build_backend_payload, interpret_request
    from app.controller.llm import AgentLLM
    from app.controller.prompts import load_input_prompt
except ModuleNotFoundError:
    from controller.interpreter import build_backend_payload, interpret_request
    from controller.llm import AgentLLM
    from controller.prompts import load_input_prompt


PAYLOAD_KEYS = {
    "repo_url",
    "token",
    "packages",
    "package_name",
    "package_version",
    "ecosystem",
    "file_name",
    "file_content",
    "mode",
    "raw_text",
}
MODES = {"fast", "detailed", "developer"}


def _extract_json(raw_text: str) -> Dict[str, Any]:
    text = (raw_text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            return json.loads(text[start : end + 1])
        raise


def _empty_payload(raw_text: str) -> Dict[str, Optional[str]]:
    return {
        "repo_url": None,
        "token": None,
        "packages": None,
        "package_name": None,
        "package_version": None,
        "ecosystem": None,
        "file_name": None,
        "file_content": None,
        "mode": None,
        "raw_text": raw_text,
    }


def _normalize_packages(payload: Dict[str, Any]) -> list[Dict[str, str]]:
    normalized_packages = []
    for item in payload.get("packages") or []:
        if not isinstance(item, dict):
            raise ValueError("Each package entry must be an object.")
        normalized_packages.append(
            {
                "package_name": str(item.get("package_name") or "").strip(),
                "package_version": str(item.get("package_version") or "").strip(),
                "ecosystem": str(item.get("ecosystem") or "").strip(),
            }
        )
    if normalized_packages:
        return normalized_packages

    package_name = str(payload.get("package_name") or "").strip()
    package_version = str(payload.get("package_version") or "").strip()
    ecosystem = str(payload.get("ecosystem") or "").strip()
    if package_name or package_version or ecosystem:
        return [
            {
                "package_name": package_name,
                "package_version": package_version,
                "ecosystem": ecosystem,
            }
        ]
    return []


def validate_input_decision(decision: Dict[str, Any], raw_text: str) -> Dict[str, Any]:
    action = decision.get("action")
    if action == "clarify":
        question = str(decision.get("question") or "").strip()
        if not question:
            raise ValueError("Clarification action requires a question.")
        return {"action": "clarify", "question": question, "backend_payload": _empty_payload(raw_text)}

    if action != "execute":
        raise ValueError("LLM decision action must be clarify or execute.")

    payload = decision.get("backend_payload")
    if not isinstance(payload, dict):
        raise ValueError("Execute action requires backend_payload.")
    normalized = {key: payload.get(key) for key in PAYLOAD_KEYS}
    normalized["raw_text"] = normalized.get("raw_text") or raw_text
    normalized["packages"] = _normalize_packages(payload) or None
    if normalized["packages"]:
        if len(normalized["packages"]) == 1:
            primary = normalized["packages"][0]
            normalized["package_name"] = primary["package_name"]
            normalized["package_version"] = primary["package_version"]
            normalized["ecosystem"] = primary["ecosystem"]
        else:
            normalized["package_name"] = None
            normalized["package_version"] = None
            normalized["ecosystem"] = None
    if normalized.get("mode") not in MODES:
        raise ValueError("backend_payload.mode must be fast, detailed, or developer.")

    target_count = sum(
        1
        for value in [
            normalized.get("repo_url"),
            normalized.get("packages") or normalized.get("package_name") or normalized.get("package_version"),
            normalized.get("file_name") or normalized.get("file_content"),
        ]
        if value
    )
    if target_count != 1:
        raise ValueError("backend_payload must include exactly one analysis target.")
    if normalized.get("packages"):
        for item in normalized["packages"]:
            if not item["package_name"] or not item["package_version"] or not item["ecosystem"]:
                raise ValueError("Each package entry requires package_name, package_version, and ecosystem.")
    elif normalized.get("package_name") and (not normalized.get("package_version") or not normalized.get("ecosystem")):
        raise ValueError("Package payload requires package_name, package_version, and ecosystem.")
    if normalized.get("file_name") and (normalized.get("file_content") is None or not str(normalized.get("file_content")).strip()):
        raise ValueError("File payload requires file_content.")
    return {"action": "execute", "backend_payload": normalized}


def deterministic_input_decision(**kwargs: Any) -> Dict[str, Any]:
    interpretation = interpret_request(**kwargs)
    payload = build_backend_payload(interpretation)
    if interpretation.clarification_question:
        return {
            "action": "clarify",
            "question": interpretation.clarification_question,
            "backend_payload": payload,
            "mode_source": interpretation.mode_source,
            "input_type": interpretation.input_type,
        }
    return {
        "action": "execute",
        "backend_payload": payload,
        "mode_source": interpretation.mode_source,
        "input_type": interpretation.input_type,
    }


def run_input_llm_stage(
    *,
    message: str,
    structured_fields: Dict[str, Any],
    llm_client: Optional[AgentLLM],
) -> Dict[str, Any]:
    if llm_client is None:
        return deterministic_input_decision(message=message, **structured_fields)

    user_payload = {"message": message, "provided_fields": structured_fields}
    raw = llm_client.complete(system_prompt=load_input_prompt(), user_payload=user_payload)
    decision = validate_input_decision(_extract_json(raw), message)
    fallback = deterministic_input_decision(message=message, **structured_fields)
    fallback_payload = fallback.get("backend_payload", {})
    if decision["action"] == "execute":
        payload_mode = decision["backend_payload"].get("mode")
        explicit_mode = str(structured_fields.get("mode") or "").strip().lower()
        fallback_mode = fallback_payload.get("mode")
        if explicit_mode and payload_mode == explicit_mode:
            decision["mode_source"] = "explicit"
        elif fallback.get("mode_source") == "explicit" and payload_mode == fallback_mode:
            decision["mode_source"] = "explicit"
        else:
            decision["mode_source"] = "inferred"
        payload = decision["backend_payload"]
        if payload.get("repo_url"):
            decision["input_type"] = "github_repo"
        elif payload.get("packages") or payload.get("package_name"):
            decision["input_type"] = "package"
        elif payload.get("file_name"):
            decision["input_type"] = "dependency_file"
        else:
            decision["input_type"] = "unknown"
    else:
        decision["mode_source"] = fallback.get("mode_source")
        decision["mode"] = fallback_payload.get("mode")
        decision["input_type"] = fallback.get("input_type", "unknown")
    return decision
