import argparse
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

try:
    # Works when launched from repository root (python -m app.main).
    from app.agents.unified_scan_agent import run_unified_scan
    from app.agents.web_scraping_agent import run_web_scrape
    from app.controller import handle_chat_request
    from app.controller.llm import get_llm_diagnostics
    from app.models.models import (
        AgentChatRequest,
        AgentChatResponse,
        GithubScanRequest,
        GithubScanResponse,
        UnifiedScanRequest,
        UnifiedScanResponse,
        WebScrapeRequest,
        WebScrapeResponse,
    )
    from app.config import get_config
    from app.services.github_scanner import run_github_scan
except ModuleNotFoundError:
    # Works when launched from inside app/ (python main.py).
    from agents.unified_scan_agent import run_unified_scan
    from agents.web_scraping_agent import run_web_scrape
    from controller import handle_chat_request
    from controller.llm import get_llm_diagnostics
    from models.models import (
        AgentChatRequest,
        AgentChatResponse,
        GithubScanRequest,
        GithubScanResponse,
        UnifiedScanRequest,
        UnifiedScanResponse,
        WebScrapeRequest,
        WebScrapeResponse,
    )
    from config import get_config
    from services.github_scanner import run_github_scan

app = FastAPI(title="AgentShield API", description="Security analysis for GitHub repos")

config = get_config()
allowed_origins = config.cors_origins

llm_startup_diagnostics = get_llm_diagnostics()
print(
    "[AGENT LLM DIAGNOSTICS] "
    f"env_file_loaded={llm_startup_diagnostics.get('env_file_loaded')} "
    f"oci_openai_imported={llm_startup_diagnostics.get('oci_openai_imported')} "
    f"has_config_file={llm_startup_diagnostics.get('has_oci_config_file')} "
    f"config_file_exists={llm_startup_diagnostics.get('oci_config_file_exists')} "
    f"config_file_is_file={llm_startup_diagnostics.get('oci_config_file_is_file')} "
    f"config_file_readable={llm_startup_diagnostics.get('oci_config_file_readable')} "
    f"has_compartment={llm_startup_diagnostics.get('has_oci_compartment_id')} "
    f"region={llm_startup_diagnostics.get('oci_region')} "
    f"model={llm_startup_diagnostics.get('oci_model_id')} "
    f"profile={llm_startup_diagnostics.get('oci_config_profile')} "
    f"require_agent_llm={llm_startup_diagnostics.get('require_agent_llm')}",
    flush=True,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def debug_request_print(request: Request, call_next):
    print(f"[BACKEND HIT] {request.method} {request.url.path}", flush=True)
    response = await call_next(request)
    print(f"[BACKEND DONE] {request.method} {request.url.path} -> {response.status_code}", flush=True)
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "AgentShield API",
    }

@app.post("/agent/chat", response_model=AgentChatResponse, response_model_exclude_none=True)
async def agent_chat(request: AgentChatRequest) -> AgentChatResponse:
    try:
        repo_url = request.repo_url or request.start_url
        result = handle_chat_request(
            message=request.message,
            repo_url=repo_url,
            token=request.token,
            packages=request.packages,
            package_name=request.package_name,
            package_version=request.package_version,
            ecosystem=request.ecosystem,
            file_name=request.file_name,
            file_content=request.file_content,
            mode=request.mode.value if request.mode else None,
            include_debug=request.include_debug,
        )
        return AgentChatResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan", response_model=UnifiedScanResponse)
async def scan(request: UnifiedScanRequest) -> UnifiedScanResponse:
    try:
        repo_url = request.repo_url or request.start_url
        result = run_unified_scan(
            raw_text=request.raw_text,
            repo_url=repo_url,
            token=request.token,
            packages=request.packages,
            package_name=request.package_name,
            package_version=request.package_version,
            ecosystem=request.ecosystem,
            file_name=request.file_name,
            file_content=request.file_content,
            mode=request.mode,
        )
        return UnifiedScanResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/github", response_model=GithubScanResponse)
async def scan_github_repo(request: GithubScanRequest) -> GithubScanResponse:
    try:
        print("Received GitHub scan request for repo:", request.repo_url, flush=True)
        result = run_github_scan(repo_url=request.repo_url, token=request.token)
        return GithubScanResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scan/web", response_model=WebScrapeResponse)
async def scrape_website(request: WebScrapeRequest) -> WebScrapeResponse:
    try:
        print("Received web scrape request for repo:", request.repo_url, flush=True)
        repo_url = request.repo_url or request.start_url
        if not repo_url:
            raise HTTPException(status_code=400, detail="repo_url is required")

        print("Received web scraping request for repo:", repo_url, flush=True)
        github_scan_report = request.github_scan_report
        if not github_scan_report:
            # Fallback path: build GitHub scan report inside /scan/web when client has no cached report.
            github_scan_result = run_github_scan(repo_url=repo_url, token=request.token)
            github_scan_report = github_scan_result.get("json_report", {})

        result = run_web_scrape(repo_url=repo_url, github_scan_report=github_scan_report)
        return WebScrapeResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def main() -> None:
    """Start the backend service with host/port from CLI args or env vars."""
    import uvicorn

    parser = argparse.ArgumentParser(description="Run backend server")
    parser.add_argument("--host", default=config.backend_host)
    parser.add_argument("--port", type=int, default=config.backend_port)
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    if args.reload:
        import os

        app_path = "main:app" if os.path.basename(os.getcwd()).lower() == "app" else "app.main:app"
        uvicorn.run(app_path, host=args.host, port=args.port, reload=True)
    else:
        uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
