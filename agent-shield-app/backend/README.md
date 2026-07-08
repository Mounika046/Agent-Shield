# AgentShield backend

AgentShield is a FastAPI service that discovers project dependencies, checks
them for known vulnerabilities, detects open-source licenses, and evaluates a
configurable engineering license policy. It accepts a GitHub repository, a
dependency file, or explicit package coordinates.

## What the backend does

- Tries GitHub's dependency-graph SBOM endpoint first, then falls back to
  finding and parsing dependency files in the repository.
- Supports Python, JavaScript, Java/Maven, and Conda dependency formats,
  including `requirements.txt`, `pyproject.toml`, `poetry.lock`,
  `Pipfile.lock`, `package.json`, `package-lock.json`, `pom.xml`, and Conda
  environment files.
- Queries OSV for exact package versions and enriches results with NVD data.
- Returns `vulnerability_scan`, `partial_discovery`, or `discovery_only` so a
  repository with unresolved versions is never presented as a clean CVE scan.
- Uses SPDX fields from GitHub SBOMs and deps.dev metadata for license detection.
- Classifies licenses as allowed, review, or denied through environment-configured policy lists.
- Uses deps.dev and GitHub metadata for the more detailed scan modes.
- Provides a conversational controller that can optionally use an OCI-hosted
  model. Core scanning remains available without that model.

## Project layout

```text
app/
  agents/       Scan workflows
  controller/   Conversational request handling and optional OCI model access
  graph/        Scan state and routing
  models/       FastAPI request and response models
  parsers/      Dependency-file parsers
  services/     GitHub acquisition, vulnerability research, and enrichment
  utils/        Repository and package utilities
tests/          Backend route and workflow tests
```

## Setup

Python 3.11 or newer is recommended.

```powershell
cd "C:\Users\Mounika\PycharmProjects\Agent Shield\agent-shield-app\backend"
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` if you need a default GitHub PAT, non-default server settings, an
NVD API key, or OCI model integration. Local `.env`, `.oci`, and PEM files are ignored by Git.
Never commit private keys or access tokens.

## Run

```powershell
python -m app.main
```

The API starts at `http://127.0.0.1:8070` by default. Interactive API
documentation is available at `http://127.0.0.1:8070/docs`.

## API endpoints

- `GET /health` — lightweight readiness check for the frontend.
- `POST /scan` — unified scan for a repository, dependency file, or packages.
- `POST /agent/chat` — conversational entry point over the unified scan.
- `POST /scan/github` — legacy GitHub repository scan.
- `POST /scan/web` — legacy web-enrichment scan.

Example unified repository scan:

```powershell
$body = @{
  repo_url = "https://github.com/owner/repository"
  token = "github_pat_optional_for_public_repositories"
  mode = "fast"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8070/scan" `
  -ContentType "application/json" `
  -Body $body
```

Example dependency-file scan:

```powershell
$body = @{
  file_name = "requirements.txt"
  file_content = "fastapi==0.104.1`nrequests==2.31.0"
  mode = "fast"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8070/scan" `
  -ContentType "application/json" `
  -Body $body
```

Set `GITHUB_TOKEN` in `.env` to use one PAT by default. A request can still
provide the `token` field to override that value for a single scan.

## Tests

```powershell
python -m unittest discover -s tests -v
```

The integrated Nitro frontend is in `..\frontend`. The `/agent/chat` backend
endpoint is retained for the planned conversational UI step; the current UI
uses `/scan`.
