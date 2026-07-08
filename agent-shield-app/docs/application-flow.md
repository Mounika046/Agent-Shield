# AgentShield application flow

This document describes the current integrated application in `agent-shield-app`.
The manual scan and conversational agent are separate user experiences, but both
reuse the same backend scan pipeline.

## 1. Complete end-to-end flow

```mermaid
flowchart TB
    U[User opens AgentShield] --> FE[Nitro Redwood React frontend]
    FE --> HEALTH[GET /api/health]
    HEALTH --> STATUS[Show backend connected or offline]

    subgraph MANUAL[Manual scan path]
        M1[Choose input source] --> M2{Input source}
        M2 -->|GitHub repository| MREPO[Repository URL and optional PAT override]
        M2 -->|Dependency file| MFILE[Read uploaded file name and content]
        M2 -->|Paste dependencies| MPASTE[Raw dependency text]
        M2 -->|Direct packages| MPKG[Package name, exact version and ecosystem]
        MREPO --> MMODE[Choose Fast, Detailed or Developer]
        MFILE --> MMODE
        MPASTE --> MMODE
        MPKG --> MMODE
        MMODE --> MREQ[Build structured ScanRequest]
        MREQ --> MSCAN[POST /api/scan]
    end

    subgraph CHAT[Independent chat path]
        C1[Enter natural-language request] --> CREQ[Build AgentChatRequest with message only]
        CREQ --> CCHAT[POST /api/agent/chat]
        CCHAT --> CONTROL[Conversational controller]
        CONTROL --> INTERPRET{Target clear and valid?}
        INTERPRET -->|No| CLARIFY[Return one clarification question]
        INTERPRET -->|Yes| CEXEC[Build one validated scan payload]
    end

    MSCAN --> API[FastAPI API layer]
    CEXEC --> SHARED[Shared run_unified_scan pipeline]
    API --> SHARED

    SHARED --> REPORT[Structured JSON report and summary]
    REPORT --> MRESP[Manual ScanResponse]
    MRESP --> MTABLE1[1. Discovered dependencies]
    MRESP --> MTABLE2[2. Vulnerable dependencies]
    MRESP --> MTABLE3[3. Open-source license compliance]

    REPORT --> CHATWRITE{OCI output model available?}
    CHATWRITE -->|Yes| OCIWRITE[OCI model writes sectioned explanation]
    CHATWRITE -->|No| FALLBACKWRITE[Deterministic formatter writes response]
    OCIWRITE --> CRESP[AgentChatResponse]
    FALLBACKWRITE --> CRESP
    CLARIFY --> CRESP
    CRESP --> CPANEL[Render only in chat panel or expanded drawer]

    CPANEL --> ISOLATED[Chat results remain separate from manual results]
```

Important separation:

- A manual scan updates the inventory, vulnerability and license tables.
- A chat scan stays inside the chat panel and expanded drawer.
- Chat does not read or replace the manual form or manual table results.

## 2. Shared backend scan pipeline

```mermaid
flowchart TB
    START[run_unified_scan] --> NORMALIZE[Normalize request context]
    NORMALIZE --> CLASSIFY[Infer input type and resolve scan mode]
    CLASSIFY --> INPUT{Input type}

    INPUT -->|GitHub repository| REPO[Acquire repository dependencies]
    INPUT -->|Dependency file or pasted list| FILE[Parse dependency content]
    INPUT -->|Direct package coordinates| PACKAGE[Build direct package inventory]
    INPUT -->|Unknown| FORMAT

    subgraph GITHUB[GitHub acquisition]
        REPO --> SBOM[Call GitHub dependency graph SBOM API]
        SBOM --> SBOMOK{SBOM available and parseable?}
        SBOMOK -->|Yes| SBOMINV[Normalize SBOM packages, versions, relationships and SPDX fields]
        SBOMOK -->|No| TREE[Read repository tree and locate dependency files]
        TREE --> FETCH[Fetch supported manifests and lockfiles]
        FETCH --> PARSE[Run dependency-file parsers]
        PARSE --> FILEINV[Create fallback repository inventory]
    end

    FILE --> FILEPARSER[Select parser from file name]
    FILEPARSER --> FILEDEPS[Normalize parsed dependencies]
    PACKAGE --> PKGDEPS[Normalize package, version and ecosystem]

    SBOMINV --> RESULTTYPE
    FILEINV --> RESULTTYPE
    FILEDEPS --> RESULTTYPE
    PKGDEPS --> RESULTTYPE

    RESULTTYPE{Exact-version coverage}
    RESULTTYPE -->|All usable exact versions| VSCAN[vulnerability_scan]
    RESULTTYPE -->|Exact and unresolved versions mixed| PARTIAL[partial_discovery]
    RESULTTYPE -->|No exact versions| DISCOVERY[discovery_only]

    VSCAN --> LICENSELOOKUP[Look up missing license metadata with deps.dev]
    PARTIAL --> LICENSELOOKUP
    DISCOVERY --> LICENSELOOKUP

    LICENSELOOKUP --> CANVULN{Reliable exact versions available?}
    CANVULN -->|No, discovery only| FORMAT[Build final report]
    CANVULN -->|Yes| OSV[Query OSV for each exact package version]
    OSV --> NVD[Enrich unique CVE IDs through NVD within lookup limits]
    NVD --> MODE{Scan mode}

    MODE -->|Fast| FORMAT
    MODE -->|Detailed| DEPSDEV[Full deps.dev package metadata enrichment]
    MODE -->|Developer| DEPSDEV
    DEPSDEV --> DEVONLY{Developer mode?}
    DEVONLY -->|No| FORMAT
    DEVONLY -->|Yes and repository input| GHINFO[GitHub repository metadata enrichment]
    DEVONLY -->|Yes but no repository| FORMAT
    GHINFO --> FORMAT

    FORMAT --> LICENSE[Build license compliance analysis]
    LICENSE --> CONTEXT[Build compact LLM context and recommendations]
    CONTEXT --> OUTPUT[Return json_report and summary]
```

### Supported dependency-file parsing

The parser layer recognizes the supported file names and routes their content to
the corresponding parser. Current examples include:

- Python: `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`
- JavaScript/npm: `package.json`, `package-lock.json`
- Maven: `pom.xml`
- Conda: `environment.yml`, `environment.yaml`, and Conda lock-file variants

Every parsed package is normalized to a common dependency model containing its
name, version, version quality, ecosystem, source type, relationship and file path.

## 3. Vulnerability flow

```mermaid
flowchart LR
    INV[Normalized dependencies] --> EXACT{Version quality}
    EXACT -->|Exact| OSV[Concurrent OSV queries]
    EXACT -->|Range or missing| SKIP[Record skipped package and coverage warning]
    OSV --> FINDINGS[Package vulnerability findings]
    FINDINGS --> CVES[Collect unique CVE IDs]
    CVES --> LIMIT[Apply NVD lookup count and time budgets]
    LIMIT --> NVD[Concurrent NVD enrichment]
    NVD --> SEVERITY[Add descriptions, CVSS and severity where available]
    SEVERITY --> VRESULT[VulnerabilityResearch]
    SKIP --> VRESULT
```

The system does not claim that an unresolved dependency is safe. Missing or
range versions are reported as incomplete coverage, and an inventory with no
exact versions becomes `discovery_only`.

## 4. License-compliance flow

```mermaid
flowchart TB
    DEP[Each discovered dependency] --> SPDX{Usable SPDX fields in GitHub SBOM?}
    SPDX -->|Yes| SBOMLICENSE[Use declared, concluded or file license data]
    SPDX -->|No| DEPSLICENSE[Use deps.dev version metadata]
    SBOMLICENSE --> IDS[Normalize license expressions and identifiers]
    DEPSLICENSE --> IDS
    IDS --> POLICY{Compare with configured policy lists}
    POLICY -->|Allowed identifier| ALLOWED[allowed]
    POLICY -->|Denied identifier| DENIED[denied]
    POLICY -->|Review list, LicenseRef, unknown or unclassified| REVIEW[review]
    ALLOWED --> TOTALS[Aggregate compliance totals]
    DENIED --> TOTALS
    REVIEW --> TOTALS
    TOTALS --> OVERALL{Overall result}
    OVERALL -->|No dependencies| NONE[no_dependencies]
    OVERALL -->|Any denied| BLOCKED[blocked]
    OVERALL -->|No denied, any review| REVIEWREQ[review_required]
    OVERALL -->|All allowed| PASSED[passed]
```

The allow, review and deny lists come from backend environment configuration.
The result is an engineering policy signal and not a legal opinion.

## 5. Conversational-agent flow

```mermaid
flowchart TB
    QUESTION[Independent chat message] --> LLMSTATUS{OCI model available?}
    LLMSTATUS -->|Yes| INPUTLLM[OCI input stage extracts target and mode]
    LLMSTATUS -->|No| DETINPUT[Deterministic interpreter extracts target and mode]
    INPUTLLM --> VALIDATE[Validate JSON decision]
    DETINPUT --> DECISION
    VALIDATE --> TARGETS{Exactly one complete target?}
    TARGETS -->|No| ASK[Return clarification; backend scan not called]
    TARGETS -->|Yes| DECISION[Execute decision]
    DECISION --> SCAN[Call shared run_unified_scan]
    SCAN --> STRUCTURED[Structured scan result]
    STRUCTURED --> WRITER{OCI output stage available?}
    WRITER -->|Yes| LLMANSWER[Generate sectioned explanation from bounded LLM context]
    WRITER -->|No| DETANSWER[Use deterministic response formatter]
    LLMANSWER --> SANITIZE[Redact tokens and sensitive payload fields]
    DETANSWER --> SANITIZE
    SANITIZE --> CHATRESPONSE[Return status, message, mode, input type and response metadata]
    CHATRESPONSE --> CHATUI[Compact preview or expanded Nitro drawer]
```

Mode inference for chat:

- `fast` for a normal vulnerability or CVE check
- `detailed` when the user asks for licenses, metadata, trust or package health
- `developer` when the user asks for deeper engineering or repository context
- An explicitly supplied mode wins over model inference

## 6. What changes by mode

| Stage | Fast | Detailed | Developer |
|---|---:|---:|---:|
| Dependency discovery and normalization | Yes | Yes | Yes |
| License metadata lookup and compliance | Yes | Yes | Yes |
| Exact-version OSV matching | Yes | Yes | Yes |
| NVD enrichment | Yes | Yes | Yes |
| Full deps.dev metadata enrichment | No | Yes | Yes |
| GitHub repository metadata enrichment | No | No | Yes, for repository input |
| Developer/provider-plan details | No | No | Yes |

## 7. Final report and UI mapping

`format_output_node` returns two top-level values:

- `json_report`: structured data used by the frontend
- `summary`: short scan completion summary

The manual frontend maps the report in this order:

1. **Discovered dependencies** — normalized inventory and version quality
2. **Vulnerable dependencies** — exact-version findings, severity and IDs
3. **Open-source license compliance** — detected license, policy status and source

Additional summary cards show dependency count, exact-version count, packages
checked and unique CVE count. Discovery-only and partial-discovery warnings are
shown explicitly above the tables.

## 8. External systems and configuration

```mermaid
flowchart LR
    APP[AgentShield backend] --> GH[GitHub API: SBOM, repository tree, file content and repository metadata]
    APP --> OSV[OSV API: package-version advisories]
    APP --> NVD[NVD API: CVE enrichment]
    APP --> DEPS[deps.dev API: versions, licenses, links and package metadata]
    APP --> OCI[Optional OCI-hosted model: chat interpretation and response writing]
    ENV[backend .env and OCI config] --> APP
```

Relevant configuration includes the default GitHub token, optional NVD key,
OCI model configuration, CORS/backend settings, provider limits and the license
allow/review/deny lists. Secrets stay in `backend/.env` or the local OCI config
and must not be included when sharing the application.

## 9. Short presentation script

1. The user chooses a repository, dependency file, pasted list or direct package.
2. The frontend sends a structured request to FastAPI.
3. The backend normalizes the request and creates a common dependency inventory.
4. Repository scans try GitHub SBOM first and fall back to parsing repository files.
5. License metadata is taken from SBOM SPDX fields or deps.dev and checked against policy.
6. Only exact package versions are sent to OSV; CVE IDs are enriched through NVD.
7. Detailed mode adds full deps.dev metadata, while Developer mode also adds GitHub context.
8. The backend returns one structured report for inventory, security and compliance tables.
9. Chat is an independent interface that interprets natural language and reuses the same scan pipeline without changing manual results.

## 10. Main implementation files

- Frontend orchestration: `frontend/src/components/AgentShieldWorkspace.tsx`
- Frontend API client: `frontend/src/api/agentShieldApi.ts`
- FastAPI routes: `backend/app/main.py`
- Unified LangGraph workflow: `backend/app/agents/unified_scan_agent.py`
- GitHub SBOM and file fallback: `backend/app/services/github/acquisition.py`
- File parsing: `backend/app/parsers/dependency_parsers.py`
- Vulnerability research: `backend/app/services/vulnerability/research.py`
- deps.dev enrichment: `backend/app/services/enrichment/deps_dev.py`
- License compliance: `backend/app/services/license_analysis.py`
- Report and LLM context: `backend/app/services/reporting.py`
- Chat controller: `backend/app/controller/chat_controller.py`
