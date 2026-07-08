import json
from typing import Any, Dict, Optional

try:
    from oci_openai import OciOpenAI, OciUserPrincipalAuth
except Exception:
    OciOpenAI = None
    OciUserPrincipalAuth = None

try:
    from app.config import AppConfig, get_config
    from app.schemas import VulnerabilityResearch
except ModuleNotFoundError:
    from config import AppConfig, get_config
    from schemas import VulnerabilityResearch


def run_oci_analysis(
    package_version_map: Dict[str, str],
    vulnerability_research: VulnerabilityResearch,
    config: Optional[AppConfig] = None,
) -> Dict[str, Any]:
    settings = config or get_config()
    if not package_version_map:
        return {"status": "skipped", "reason": "No packages found for OCI analysis."}

    if OciOpenAI is None or OciUserPrincipalAuth is None:
        return {"status": "skipped", "reason": "oci_openai package is not available in this environment."}

    if not settings.oci_config_file or not settings.oci_compartment_id:
        return {"status": "skipped", "reason": "OCI configuration is not set."}

    try:
        client = OciOpenAI(
            region=settings.oci_region,
            auth=OciUserPrincipalAuth(
                config_file=settings.oci_config_file,
                profile_name=settings.oci_config_profile,
            ),
            compartment_id=settings.oci_compartment_id,
        )

        compact_research = {
            "ecosystem": vulnerability_research.ecosystem,
            "packages_with_vuln_counts": [
                {
                    "package_name": item.package_name,
                    "version_checked": item.version_checked,
                    "vulnerability_count": item.vulnerability_count,
                    "cve_ids": item.cve_ids,
                }
                for item in vulnerability_research.packages_checked
            ][:25],
            "cves_found": vulnerability_research.cves_found[:50],
            "nvd_details": [item.model_dump() for item in vulnerability_research.nvd_details[:20]],
        }

        prompt = (
            "You are a security analyst. Review dependencies and vulnerability findings, then provide:\n"
            "1) overall risk level, 2) top risky packages with reason, 3) immediate remediation actions.\n"
            f"package_version_map: {json.dumps(package_version_map)}\n"
            f"vulnerability_research: {json.dumps(compact_research)}"
        )
        response = client.responses.create(
            model=settings.oci_model_id,
            store=False,
            input=[{"role": "user", "content": prompt}],
        )

        output_text = getattr(response, "output_text", "") or ""
        return {
            "status": "success",
            "model_id": settings.oci_model_id,
            "summary": str(output_text).strip(),
        }
    except Exception as exc:
        return {
            "status": "failed",
            "reason": str(exc),
            "config_file": settings.oci_config_file,
            "profile_name": settings.oci_config_profile,
        }
