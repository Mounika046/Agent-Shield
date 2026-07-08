import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool = False) -> bool:
    raw_value = os.getenv(name, "").strip().lower()
    if not raw_value:
        return default
    return raw_value in {"1", "true", "yes", "on"}


def _load_env_file() -> tuple[bool, str]:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return False, str(env_path)
    override_existing = _env_bool("APP_ENV_OVERRIDE", True)
    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if override_existing or key not in os.environ:
                os.environ[key] = value
        return True, str(env_path)
    except OSError:
        return False, str(env_path)


ENV_FILE_LOADED, ENV_FILE_PATH = _load_env_file()


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default


@dataclass(frozen=True)
class AppConfig:
    cors_allow_origins: str = os.getenv(
        "CORS_ALLOW_ORIGINS",
        "http://localhost:5200,http://127.0.0.1:5200,http://localhost:5173,http://127.0.0.1:5173",
    )
    backend_host: str = os.getenv("BACKEND_HOST", "127.0.0.1")
    backend_port: int = _env_int("BACKEND_PORT", 8070)
    request_timeout_seconds: int = _env_int("REQUEST_TIMEOUT", 20)
    osv_url: str = os.getenv("OSV_URL", "https://api.osv.dev/v1/query")
    nvd_url: str = os.getenv("NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    nvd_api_key: str = os.getenv("NVD_API_KEY", "").strip()
    github_token: str = os.getenv("GITHUB_TOKEN", "").strip()
    max_research_packages: int = _env_int("MAX_RESEARCH_PACKAGES", 20)
    max_license_packages: int = _env_int("MAX_LICENSE_PACKAGES", 20)
    license_denied: str = os.getenv(
        "LICENSE_DENIED",
        "AGPL-3.0-ONLY,AGPL-3.0-OR-LATER,SSPL-1.0",
    )
    license_allowed: str = os.getenv(
        "LICENSE_ALLOWED",
        "MIT,APACHE-2.0,BSD-2-CLAUSE,BSD-3-CLAUSE,ISC,0BSD,UNLICENSE,ZLIB,CC0-1.0,PSF-2.0,PYTHON-2.0",
    )
    license_review: str = os.getenv(
        "LICENSE_REVIEW",
        "GPL-2.0-ONLY,GPL-2.0-OR-LATER,GPL-3.0-ONLY,GPL-3.0-OR-LATER,LGPL-2.1-ONLY,LGPL-3.0-ONLY,MPL-2.0,EPL-2.0,CDDL-1.0,EUPL-1.2",
    )
    max_nvd_lookups: int = _env_int("MAX_NVD_LOOKUPS", 10)
    nvd_total_budget_seconds: int = _env_int("NVD_TOTAL_BUDGET_SECONDS", 45)
    nvd_max_retries: int = _env_int("NVD_MAX_RETRIES", 4)
    nvd_base_backoff_seconds: float = float(os.getenv("NVD_BASE_BACKOFF_SECONDS", "1.5"))
    osv_max_workers: int = _env_int("OSV_MAX_WORKERS", 6)
    nvd_max_workers_with_key: int = _env_int("NVD_MAX_WORKERS_WITH_KEY", 3)
    nvd_max_workers_no_key: int = _env_int("NVD_MAX_WORKERS_NO_KEY", 1)
    oci_config_file: str = os.getenv("OCI_CONFIG_FILE", "")
    oci_region: str = os.getenv("OCI_REGION", "us-chicago-1")
    oci_model_id: str = os.getenv("OCI_MODEL_ID", "openai.gpt-5.2")
    oci_compartment_id: str = os.getenv("OCI_COMPARTMENT_ID", "ocid1.compartment.oc1..aaaaaaaakqloyfwdhn3buelfhd27z2irt4vnlxvkt6b5weefcyj5qaj57pfa")
    oci_config_profile: str = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
    require_agent_llm: bool = _env_bool("REQUIRE_AGENT_LLM")
    env_file_loaded: bool = ENV_FILE_LOADED
    env_file_path: str = ENV_FILE_PATH

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_allow_origins.split(",") if origin.strip()]

    @property
    def nvd_max_workers(self) -> int:
        default_workers = self.nvd_max_workers_with_key if self.nvd_api_key else self.nvd_max_workers_no_key
        return _env_int("NVD_MAX_WORKERS", default_workers)


def get_config() -> AppConfig:
    return AppConfig()
