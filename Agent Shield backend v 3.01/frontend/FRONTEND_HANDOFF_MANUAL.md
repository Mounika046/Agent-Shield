# AgentShield Frontend Setup

## Prerequisites

- Install [Bun](https://bun.sh/).
- Connect to the Oracle network/VPN so Bun can download the internal Nitro
  packages configured in `.npmrc`.
- Make sure the AgentShield backend is running.

## Setup and run

Open PowerShell in the frontend folder:

```powershell
cd "C:\path\to\frontend"
bun install
bun run dev
```

Open the application at:

```text
http://127.0.0.1:5200
```

## Backend connection

By default, the frontend connects to:

```text
http://127.0.0.1:8070
```

Verify the backend before starting the UI:

```powershell
Invoke-RestMethod http://127.0.0.1:8070/health
```

If the backend uses another address or port, create a `.env` file in the
frontend folder:

```dotenv
VITE_API_BASE_URL=http://backend-hostname:8070
```

Restart `bun run dev` after changing `.env`. The backend must allow
`http://127.0.0.1:5200` in its CORS configuration.

## Build check

```powershell
bun run build
```

## Important

- Do not put GitHub PAT, NVD, OCI, or other credentials in the frontend `.env`.
- If `bun install` fails for `@idp/*`, check Oracle VPN and internal registry
  access.
- If the UI shows **Backend disconnected**, verify `/health`, the backend port,
  `VITE_API_BASE_URL`, and backend CORS.
