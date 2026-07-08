# AgentShield project and session handoff

This document is the working context for continuing AgentShield on another
system or in a new AI-assisted development session. It summarizes the relevant
technical decisions and implementation work from the project conversation.
Intermediate requests for drafting messages have intentionally been omitted.

## 1. Source of truth

The complete application to copy and continue working on is:

```text
agent-shield-app/
  backend/     FastAPI and LangGraph backend
  frontend/    React, TypeScript, Vite, Bun, and Nitro Redwood frontend
  docs/        Architecture, workflow, and handoff documentation
```

Use `agent-shield-app` as the source of truth. The following sibling folders
were earlier versions, experiments, or comparison sources and are not the final
runtime application:

- `Agent Shield backend/`
- `Agent Shield backend v2/`
- `Agent Shield backend v3/`
- `Agent Shield backend v 3.01/`
- `agent-shield-ui/`
- `scripts/github_api_checks/`

The application currently contains the v3.01 functionality merged into the
customized Nitro frontend. Do not replace the customized frontend wholesale
with the frontend from an older or upstream backend folder.

## 2. Product purpose

AgentShield analyzes open-source project dependencies and returns two primary
results:

1. Known vulnerability/CVE findings for exact package versions.
2. Open-source license compliance results based on a configurable engineering
   policy.

It supports both a deterministic manual scan workflow and an OCI-assisted
natural-language agent workflow.

This is an engineering risk signal, not legal advice. License decisions must
still follow the organization's legal and compliance process.

## 3. User-facing workflows

### Manual scan page

Route: `#/`

The manual page supports four input methods:

- GitHub repository URL
- Dependency-file upload
- Pasted dependency text
- One or more direct package coordinates

The user selects one of three modes and submits the form. Results are displayed
in this order:

1. Discovered dependencies
2. Vulnerable dependencies
3. Open-source license compliance

The manual scan uses `POST /scan`.

### Agent chat page

Route: `#/chat`

The chat is a real separate single-page application route implemented with
TanStack Router hash history. The `#` is intentional and makes static VM
hosting simpler because the web server does not need history-API rewrite rules.

The chat:

- accepts natural-language scan requests;
- supports dependency-file attachments;
- provides Fast, Detailed, and Developer mode selection;
- calls `POST /agent/chat`;
- renders assistant text with headings, lists, links, inline code, and code
  blocks;
- renders structured dependency, vulnerability, license, and dependency-graph
  artifacts separately from the narrative response;
- supports Enter to send and Shift+Enter for a new line;
- auto-grows and shrinks its composer;
- keeps the page fixed to the viewport while only the conversation feed
  scrolls;
- includes a return action to the manual scan page.

Chat results are intentionally independent of the manual scan page. A chat
request must not populate or modify the manual scan tables.

## 4. Analysis modes

Only these three modes are exposed to users:

### Fast

- Discovers dependencies.
- Checks exact package versions against OSV.
- Enriches available CVEs with NVD details.
- Does not run license analysis or detailed deps.dev enrichment.

### Detailed

- Includes Fast-mode vulnerability analysis.
- Adds deps.dev package metadata.
- Detects licenses and applies the configured license policy.

### Developer

- Includes Detailed-mode behavior.
- Adds repository metadata where applicable.
- Adds developer-oriented context and dependency graphs for selected vulnerable
  exact-version packages.

Developer mode is still an area for future refinement. Its longer-term goal is
deeper technical context and stronger remediation/upgrade recommendations.

An internal legacy `full` enum may still exist in backend schemas for backward
compatibility, but it is not a fourth UI mode and must not be reintroduced into
the frontend.

## 5. End-to-end backend flow

The primary API flow is:

```text
Frontend input
  -> POST /scan or POST /agent/chat
  -> classify input and mode
  -> acquire and normalize dependencies
  -> classify result quality
  -> query OSV for exact versions
  -> enrich CVEs through NVD
  -> Detailed/Developer: deps.dev metadata and license analysis
  -> Developer: selected dependency graphs and GitHub metadata
  -> format JSON report, tables, and optional natural-language response
  -> render in the frontend
```

The LangGraph workflow is implemented in:

```text
backend/app/agents/unified_scan_agent.py
```

API routes are defined in:

```text
backend/app/main.py
```

Current endpoints:

- `GET /health` - frontend/backend connectivity check
- `POST /scan` - main deterministic unified scan
- `POST /agent/chat` - conversational controller over the unified scan
- `POST /scan/github` - retained legacy GitHub scan endpoint
- `POST /scan/web` - retained legacy web-enrichment endpoint

The manual page should continue using `/scan`; the chat page should continue
using `/agent/chat`.

## 6. GitHub repository acquisition and fallback

For a GitHub repository, the backend first calls:

```text
GET /repos/{owner}/{repo}/dependency-graph/sbom
```

If GitHub's dependency graph/SBOM is unavailable or cannot be parsed, the
fallback does the following:

1. Reads repository metadata to determine the default branch.
2. Calls the Git Trees API with `recursive=1` to obtain the complete file list.
3. If GitHub marks the tree as truncated, recursively traverses subtree SHAs.
4. Searches all returned paths, including nested directories, for recognized
   dependency files.
5. Calls the Contents API only for the selected dependency files.
6. Parses and normalizes the downloaded files.

Therefore the fallback is not limited to a fixed folder depth. It attempts to
inspect the entire repository tree. GitHub API limits and inaccessible content
can still restrict the result.

Important files:

```text
backend/app/services/github/client.py
backend/app/services/github/acquisition.py
backend/app/utils/repo_utils.py
backend/app/parsers/dependency_parsers.py
```

The current parser implementation recognizes these file families:

- Python: pinned requirements files, `pyproject.toml`, `poetry.lock`, and
  `Pipfile.lock`
- Node.js: `package.json` and `package-lock.json`
- Java: `pom.xml`
- Conda: environment and conda lock YAML files

Do not claim that every package-manager format is fully parsed until the parser
and file-discovery lists are extended and tested. Some ecosystem mappings and
registry-link helpers support more ecosystems than repository-file parsing.

## 7. Vulnerability analysis

The primary vulnerability provider is OSV. Exact package name, version, and
ecosystem coordinates are sent to OSV. Results can include CVE and GHSA-style
advisory identifiers.

NVD is an enrichment provider, not the primary vulnerability fallback. It adds
available CVE details such as:

- severity;
- base score;
- description;
- publication and modification dates.

Important file:

```text
backend/app/services/vulnerability/research.py
```

There is no separate equivalent vulnerability database that automatically
replaces OSV if OSV is unavailable. The working resilience is:

- per-package error handling;
- warnings/errors in the response;
- skipping non-exact versions instead of reporting them as safe;
- NVD enrichment for identifiers already found.

The backend classifies output quality as:

- `vulnerability_scan` - exact-version vulnerability checks were possible;
- `partial_discovery` - some dependencies could be checked and others could
  not;
- `discovery_only` - dependencies were found but versions were insufficient for
  a valid exact-version scan.

This distinction is important: unresolved versions must never be presented as
"no vulnerabilities found."

## 8. License analysis

License analysis runs only in Detailed and Developer modes. This is intentional.

License evidence comes from available SPDX information in GitHub SBOM data and
from deps.dev package metadata. The policy classifies findings as:

- `Allowed`
- `Review required`
- `Denied`

Policy lists are configured through:

```text
LICENSE_ALLOWED
LICENSE_REVIEW
LICENSE_DENIED
```

The frontend accepts the current title-case statuses and retains compatibility
with older lowercase responses.

Important files:

```text
backend/app/services/license_analysis.py
backend/app/services/reporting.py
```

## 9. v3.01 improvements already integrated

All meaningful v3.01 features were merged into `agent-shield-app` while
preserving the customized frontend.

### Dependency graphs

Developer mode can query the deps.dev dependency graph endpoint:

```text
GET https://api.deps.dev/v3/systems/{system}/packages/{package}/versions/{version}:dependencies
```

Current limits are deliberate:

- only vulnerable exact-version packages are selected;
- at most 5 packages are graphed;
- at most 10 direct dependencies are retained for each package;
- asynchronous HTTP calls use concurrency control, retry/backoff, and a
  process-local cache.

This is not a complete repository-wide transitive dependency graph.

Backend implementation:

```text
backend/app/services/dependency_graph/deps_graph.py
```

Frontend implementation:

```text
frontend/src/components/v3/DependencyGraphView.tsx
frontend/src/components/v3/ResponseArtifacts.tsx
```

The graph visualization uses native responsive SVG. An attempted
`react-force-graph-2d` install failed because the configured registry refused
the package request, so the external dependency was not retained.

### Registry links

Discovered-dependency tables can include ecosystem-aware package registry links
for PyPI, npm, Maven, Go, Cargo, RubyGems, and NuGet.

### Structured chat output

The chat response can contain:

- summary cards;
- discovered-dependency table;
- vulnerable-dependency table with CVE details;
- license-compliance table;
- Developer-mode dependency graph data;
- formatted OCI or deterministic narrative response.

## 10. OCI-assisted agent behavior

OCI Generative AI is used by the conversational controller for input
interpretation and natural-language output when configured. Core deterministic
scanning remains usable when the model is unavailable unless
`REQUIRE_AGENT_LLM=true` is explicitly set.

`REQUIRE_AGENT_LLM=false` means model failure does not prevent deterministic
scans from completing.

The agent should never invent repository URLs, credentials, package versions,
ecosystems, filenames, or file contents.

The chat UI sends its selected mode, but the v3.01 controller also contains
mode-inference behavior for conversational testing. If strict user-selected
mode precedence is required later, review the interpreter/controller flow and
make the UI-selected mode authoritative.

Important files:

```text
backend/app/controller/chat_controller.py
backend/app/controller/interpreter.py
backend/app/controller/llm.py
backend/app/controller/prompts_input.txt
backend/app/controller/prompts_output.txt
backend/app/controller/prompts_output_detailed.txt
backend/app/controller/prompts_output_developer.txt
```

## 11. Frontend design and important decisions

The frontend uses Oracle Nitro Redwood components and theme infrastructure. It
is React-based; `.tsx` files are React components.

The manual workspace was redesigned to avoid a monotonous, overly long page.
The result hierarchy and table order should remain clear and compact.

The chat page was rebuilt as a polished AI-assistant interface rather than a
generic form or messaging app. Important retained behavior includes:

- centered, comfortable conversation width;
- full viewport use without double page/response scrolling;
- a compact floating rounded composer;
- a borderless multiline textarea that expands to a maximum of eight lines and
  shrinks after text is removed;
- compact paperclip, mode selector, and circular send controls on one toolbar;
- disabled and loading send states;
- mode descriptions available through the selector interaction rather than a
  permanently visible description below it;
- smaller narrative response typography while preserving readable table text;
- visually distinct structured tables and graph artifacts;
- Markdown-like headings, subheadings, bullets, numbered items, bold labels,
  links, URLs, inline code, and code blocks in assistant text.

Key frontend files:

```text
frontend/src/app/definition.ts
frontend/src/app/router.tsx
frontend/src/components/AgentShieldWorkspace.tsx
frontend/src/components/v3/ChatPage.tsx
frontend/src/components/v3/ChatPage.module.css
frontend/src/components/v3/Composer.tsx
frontend/src/components/v3/ModeSelector.tsx
frontend/src/components/v3/MessageBubble.tsx
frontend/src/components/v3/ResponseArtifacts.tsx
frontend/src/components/v3/TableRenderer.tsx
frontend/src/components/v3/DependencyGraphView.tsx
frontend/src/components/v3/renderMarkdownLite.tsx
frontend/src/api/agentShieldApi.ts
frontend/src/api/chat.ts
```

The API base URL is resolved in the frontend API layer. By default development
uses `/api`, which Vite proxies to the backend. `VITE_API_BASE_URL` can point to
a separately hosted backend.

## 12. Configuration and secrets

Create local environment files from the examples, but never copy real secrets
into this handoff document or commit them.

Backend configuration:

```text
backend/.env
```

Important variables:

- `BACKEND_HOST`
- `BACKEND_PORT`
- `CORS_ALLOW_ORIGINS`
- `GITHUB_TOKEN`
- `NVD_API_KEY` (optional but improves NVD rate limits)
- `LICENSE_ALLOWED`
- `LICENSE_REVIEW`
- `LICENSE_DENIED`
- `OCI_CONFIG_FILE`
- `OCI_CONFIG_PROFILE`
- `OCI_REGION`
- `OCI_MODEL_ID`
- `OCI_COMPARTMENT_ID`
- `REQUIRE_AGENT_LLM`

Frontend configuration:

```text
frontend/.env
```

Variable:

```text
VITE_API_BASE_URL=http://127.0.0.1:8070
```

The backend and frontend ports must match the actual local configuration. Some
earlier development used a non-default backend port, so verify the copied
`.env` rather than assuming `8070`.

Never place a GitHub PAT, OCI secret, or NVD key in a frontend `VITE_` variable;
Vite variables are exposed to the browser. The UI PAT field is only an optional
per-request override held in page state.

Before moving or sharing the project, exclude:

- `.env` files containing credentials;
- `.oci` directories;
- private/public PEM key material;
- `node_modules`;
- build output;
- Python caches and test caches.

## 13. New-system setup and local run

Prerequisites:

- Python 3.11 or newer
- Bun
- access to the Oracle Nitro package registry for installing Nitro packages
- network access to GitHub, OSV, NVD, and deps.dev
- OCI configuration only if the conversational model is required

No virtual environment is required by the current project instructions.

### Backend

```powershell
cd agent-shield-app\backend
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env and add only the credentials/configuration required in that system.
python -m app.main --reload
```

### Frontend

Open another PowerShell terminal:

```powershell
cd agent-shield-app\frontend
bun install
Copy-Item .env.example .env
# Ensure VITE_API_BASE_URL matches the backend URL and port.
bun run dev
```

Default local addresses from the examples are:

- frontend: `http://127.0.0.1:5200`
- backend: `http://127.0.0.1:8070`
- FastAPI docs: `http://127.0.0.1:8070/docs`

## 14. Verification

The latest successful integrated verification was:

```text
Backend: 105 tests passed
Frontend TypeScript: passed
Frontend production build: passed
```

Use these commands after moving the project or making changes:

```powershell
cd agent-shield-app\backend
python -m pytest -q tests -p no:cacheprovider
```

The disabled pytest cache avoids a Windows cache-directory permission issue
seen in this workspace.

```powershell
cd agent-shield-app\frontend
bunx tsc --noEmit
bun run build
```

`bun run verify` additionally requires the Nitro CLI and appropriate internal
registry/tooling access.

## 15. VM and orchestration deployment notes

The application is deployable on a VM, but localhost development settings must
be changed.

At minimum:

1. Set `BACKEND_HOST=0.0.0.0`.
2. Set `BACKEND_PORT` to the port assigned by the deployment/orchestration
   environment.
3. Set `CORS_ALLOW_ORIGINS` to the real frontend origin.
4. Build the frontend with `VITE_API_BASE_URL` pointing to the reachable backend
   URL, or configure a reverse proxy for `/api`.
5. Permit the required ports in VM/network security rules.
6. Run the backend and static frontend under the team's process supervisor,
   reverse proxy, container, or orchestration approach rather than relying on
   development terminals.
7. Provision credentials through the deployment platform's secret mechanism;
   do not upload the local `.env` or OCI private key casually.

The current hash-based routes are suitable for simple static hosting. If routing
is later changed to clean browser-history URLs, the web server must return
`index.html` for frontend routes such as `/chat`.

The broader team has indicated that the full frontend/backend application may
be integrated through orchestration and that this workstream may only need to
deliver the code files to the VM. Confirm the assigned VM, ports, environment
variables, secret provisioning, and expected artifact format before deployment.

## 16. Demonstration coverage

Useful repository demonstrations previously selected were:

- `https://github.com/hashicorp/terraform` - repository with dependency graph
  support
- `https://github.com/Surya-Mounika/Multi-Agent-Application` - repository used
  to demonstrate the dependency-file fallback when GitHub dependency graph is
  unavailable

Other useful cases:

- direct package: PyPI `requests==2.31.0`
- pasted dependencies: exact pinned requirements such as
  `requests==2.31.0` and `fastapi==0.104.1`
- uploaded dependency file: a pinned `requirements.txt` or lockfile
- non-exact dependency: a range such as `requests>=2.31.0` to demonstrate
  partial/discovery-only warnings
- Detailed mode: verify deps.dev metadata and license compliance
- Developer mode: use a vulnerable exact package and verify graph artifacts
  when deps.dev graph data is available

Detailed and Developer calls can take longer because they make additional
network requests. For a live demo, pre-run those cases in separate browser tabs
and keep the completed results available.

## 17. Known limitations and cautions

- Repository fallback parsing does not yet cover every dependency-file format.
- OSV has no equivalent automatic vulnerability-provider fallback.
- NVD rate limiting is more restrictive without an API key.
- Only exact versions receive confident vulnerability matching.
- Developer dependency graphs cover selected vulnerable packages, not every
  dependency in the repository.
- Developer mode needs further product differentiation and deeper remediation
  guidance.
- OCI output quality depends on model availability and prompt behavior;
  deterministic tables remain the evidence source.
- The chat controller's mode inference should be revisited if strict UI mode
  precedence becomes a product requirement.
- Existing README text may lag behind the latest separate chat page and v3.01
  graph integration; verify code behavior before relying on an older sentence.
- Never report a partial or discovery-only result as a clean security result.

## 18. Future work already identified

Priority future work:

1. Complete Developer mode with deeper GitHub and dependency context.
2. Add developer-focused remediation and safe upgrade recommendations.
3. Extend and test repository parsing for additional package managers.
4. Decide whether UI-selected chat mode must always override LLM inference.
5. Add a true secondary vulnerability provider if required.
6. Finalize VM/orchestration deployment configuration and production serving.
7. Keep the manual and chat experiences independent while sharing backend
   evidence models.

Possible chat extensibility already considered:

- conversation history;
- prompt suggestions;
- retry/regenerate;
- response reactions;
- repository picker;
- drag-and-drop attachments;
- voice input;
- security-profile or tool selectors.

These were not required for the current working version and should not clutter
the existing interface unless prioritized.

## 19. Existing project documentation

Additional diagrams and explanations are already available in `docs/`:

- `application-flow.md` - technical application flow
- `agent-shield-flow.svg` and `agent-shield-complete-flow.png` - complete flow
- `agent-shield-user-workflow.svg` and `agent-shield-workflow-final.png` - user
  workflow
- `agent-shield-analysis-workflow.svg` and
  `agent-shield-analysis-workflow.png` - core analysis/output workflow

## 20. Copy-ready context for a new development session

Use the following prompt after opening the copied project on the new system:

> Continue work on the AgentShield project in `agent-shield-app`. Read
> `docs/PROJECT_SESSION_HANDOFF.md` completely before making changes. Treat
> `agent-shield-app` as the only source of truth; sibling backend version
> folders were comparison sources. Preserve the customized Nitro Redwood
> manual page and AI-style separate chat page. The application has three user
> modes only: Fast, Detailed, and Developer. License analysis is intentionally
> available only in Detailed and Developer. The v3.01 deps.dev dependency-graph
> and registry-link functionality has already been merged. Chat results must
> remain independent of manual scan results. Inspect the current code before
> proposing changes, protect credentials, and run backend tests plus frontend
> TypeScript/build verification after implementation.

