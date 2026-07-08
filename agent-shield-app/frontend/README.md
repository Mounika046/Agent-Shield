# AgentShield frontend

Nitro React frontend for the AgentShield FastAPI backend.


## Supported workflows

- Unified GitHub repository scan through `POST /scan`
- Dependency-file scan through `POST /scan`
- Pasted dependency-list scan through `POST /scan`
- Single or multiple direct-package scans through `POST /scan`
- Fast, detailed, and developer scan modes
- Backend connectivity through `GET /health`

The UI displays dependency inventory, CVE findings, version quality, detected
licenses, and license policy results returned by the backend.

## Local development

Install dependencies with Bun as required by Nitro:

```powershell
bun install
bun run dev
```

The frontend runs at `http://127.0.0.1:5200`. Vite proxies `/api` requests to
`http://127.0.0.1:8070` during development.

To call another backend directly, copy `.env.example` to `.env` and change the
URL. Do not put GitHub tokens in frontend environment files. Configure the
default PAT as `GITHUB_TOKEN` in the backend `.env`; the UI field is only an
optional per-request override held in page state.

## Verification

```powershell
bun run build
bun run verify
```

`bun run verify` requires the Nitro CLI to be available in the development
environment.
