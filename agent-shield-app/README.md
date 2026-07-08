# AgentShield

AgentShield is a Nitro React and FastAPI application for discovering project
dependencies and checking exact package versions for known vulnerabilities.

## Current capabilities

- Scan a GitHub repository using GitHub SBOM discovery with dependency-file fallback.
- Upload common Python, npm, Maven, and Conda dependency files.
- Paste a dependency list or scan one or more direct packages.
- Run fast, detailed, or developer analysis modes.
- Distinguish complete vulnerability scans, partial discovery, and discovery-only results so unresolved versions are not reported as clean.
- Query OSV and enrich CVEs through NVD.
- Use deps.dev and GitHub metadata in the applicable modes.
- Detect licenses from GitHub SPDX SBOM data or deps.dev metadata.
- Evaluate detected SPDX identifiers against configurable allow, review, and deny lists.
- Use the independent side-panel AgentShield conversation to request scans in natural language without reading or changing the manual scan form and results workspace.

License policy results are engineering signals and are not legal advice. Configure
the policy using `LICENSE_ALLOWED`, `LICENSE_REVIEW`, and `LICENSE_DENIED` in
`backend\.env` when the defaults do not match your organization.

## Structure

```text
agent-shield-app/
  frontend/              Nitro React single-page UI
  backend/               FastAPI service and tests
```

The detailed end-to-end architecture and runtime diagrams are available in
[`docs/application-flow.md`](docs/application-flow.md).

The complete project/session context for moving development to another system
is available in
[`docs/PROJECT_SESSION_HANDOFF.md`](docs/PROJECT_SESSION_HANDOFF.md).

A presentation-ready visual diagram is available as
[`docs/agent-shield-flow.svg`](docs/agent-shield-flow.svg).
The PNG export is available as
[`docs/agent-shield-complete-flow.png`](docs/agent-shield-complete-flow.png).

The separate non-technical user workflow is available as
[`docs/agent-shield-user-workflow.svg`](docs/agent-shield-user-workflow.svg).
The share-ready PNG is
[`docs/agent-shield-workflow-final.png`](docs/agent-shield-workflow-final.png).

The standalone core analysis and output workflow is available as
[`docs/agent-shield-analysis-workflow.svg`](docs/agent-shield-analysis-workflow.svg).
The shareable PNG export is
[`docs/agent-shield-analysis-workflow.png`](docs/agent-shield-analysis-workflow.png).

## First-time setup

Requirements:

- Python 3.11 or newer
- Bun available on `PATH`

Set up the backend:

```powershell
cd "C:\Users\Mounika\PycharmProjects\Agent Shield\agent-shield-app\backend"
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set up the frontend:

```powershell
cd "C:\Users\Mounika\PycharmProjects\Agent Shield\agent-shield-app\frontend"
bun install
```

## Run the application

Open two PowerShell terminals.

Terminal 1:

```powershell
cd "C:\Users\Mounika\PycharmProjects\Agent Shield\agent-shield-app"
cd backend
python -m app.main --reload
```

Terminal 2:

```powershell
cd "C:\Users\Mounika\PycharmProjects\Agent Shield\agent-shield-app"
cd frontend
bun run dev
```

Open `http://127.0.0.1:5200`. FastAPI documentation is available at
`http://127.0.0.1:8070/docs`.

## Configuration and credentials

- Frontend development requests under `/api` are proxied to port `8070`.
- Use `frontend\.env` with `VITE_API_BASE_URL` only when calling another backend.
- Store the default GitHub PAT as `GITHUB_TOKEN` in `backend\.env`. The UI PAT field is an optional per-request override.
- Never put the PAT in `frontend\.env` or any `VITE_` variable because those values are exposed to the browser.
- Configure optional OCI integration in `backend\.env` and a local OCI config.
- `.env`, `.oci`, PEM keys, frontend dependencies, and builds are ignored.

## Verify

```powershell
cd "C:\Users\Mounika\PycharmProjects\Agent Shield\agent-shield-app\backend"
python -m unittest discover -s tests -v
```

```powershell
cd "C:\Users\Mounika\PycharmProjects\Agent Shield\agent-shield-app\frontend"
bun run build
bun run verify
```
