from typing import Any, Dict, Optional

try:
    from app.controller.formatter import format_chat_response
    from app.controller.llm import AgentLLM
    from app.controller.prompts import load_output_prompt
except ModuleNotFoundError:
    from controller.formatter import format_chat_response
    from controller.llm import AgentLLM
    from controller.prompts import load_output_prompt


def run_output_llm_stage(
    *,
    message: str,
    mode: str,
    backend_result: Dict[str, Any],
    llm_client: Optional[AgentLLM],
) -> str:
    def _sanitize_mode_answer(text: str) -> str:
        if str(mode or "").lower() in {"detailed", "developer"}:
            return text.replace("`", "")
        return text

    if llm_client is None:
        return _sanitize_mode_answer(format_chat_response(backend_result, mode))

    report = backend_result.get("json_report", {})
    llm_context = report.get("llm_context") or report
    payload = {
        "user_message": message,
        "mode": mode,
        "llm_context": llm_context,
        "dependency_summary": llm_context.get("input", {}).get("dependency_summary", {}),
        "vulnerability_details": llm_context.get("vulnerability_details", []),
        "top_findings": llm_context.get("top_findings", []),
        "top_cves": llm_context.get("top_cves", []),
        "top_vulnerabilities_grouped": llm_context.get("top_vulnerabilities_grouped", []),
        "fix_analysis": llm_context.get("fix_analysis", {}),
        "licenses": llm_context.get("licenses", []),
        "detailed_context": llm_context.get("detailed", {}),
        "vulnerable_package_summary": llm_context.get("vulnerable_package_summary", {}),
        "package_analysis": llm_context.get("package_analysis", {}),
        "top_uncertainties": llm_context.get("top_uncertainties", []),
        "important_metadata": llm_context.get("important_metadata", []),
        "recommended_next_steps": llm_context.get("recommended_next_steps", []),
        "developer_context": llm_context.get("developer", {}),
        "summary": backend_result.get("summary"),
    }
    answer = llm_client.complete(system_prompt=load_output_prompt(mode), user_payload=payload).strip()
    final_answer = answer or format_chat_response(backend_result, mode)
    return _sanitize_mode_answer(final_answer)
