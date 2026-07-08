# Agents Guide — agent-shield-ui

## CRITICAL RULES

1. **REGISTRY-FIRST: Before creating ANY UI element, ALWAYS search the @nitro registry first.**
   - Before writing a component, page, form, layout, dialog, card, or ANY piece of UI: search the registry.
   - Use `bun run shadcn:nitro -- search @nitro --query "<keywords>"` with relevant keywords (e.g. "welcome", "form", "dashboard", "chat").
   - Inspect matches with `bun run shadcn:nitro -- view @nitro/<item>`.
   - If a matching `registry:block` (page template) or `registry:ui` (component) exists, import it from `@idp/nitro-redwood` and use local wrappers, adapters, route pages, or compositions for app-specific behavior.
   - Only hand-code UI if you have searched the registry and confirmed nothing suitable exists.
   - The registry has **120+ page templates** and **130+ components** — almost everything you need already exists.
2. **ALWAYS use Nitro CLI commands** — prefer `nitro-cli <command>`, but if it fails, retry with `bunx @idp/nitro-cli@latest <command>`; never hand-author foundation files.
3. **ALWAYS run `nitro-cli verify` after every scaffold, page creation, or component wiring change** — it must exit 0.
4. **ALWAYS install dependencies with `bun install`** — Nitro scaffolds are validated against Bun and some Nitro packages may publish prerelease dist-tags such as `next`.
5. **ALWAYS prefer project-local tools** — use `bun run shadcn:nitro --` for shadcn, and `bunx cdp-cli`, `bunx playwright-cli`, and `bunx c7` from the app root.
   - See [package.json](./package.json) for the exact `shadcn:nitro` script expansion.
6. **NEVER edit `node_modules` or `@idp/nitro-redwood` package files from this app.** Create app-local wrappers and compositions instead.
7. **ALWAYS follow the AI attribution requirement before finalizing commits.**

## AI Attribution Requirement

Choose the attribution mechanism before finalizing:
- If the user or repository policy allows commit-message tracking, or the repository has a whole-codebase AI-generated baseline, use commit-message attribution.
- If the user or repository policy explicitly requires inline demarcation and no approved alternate tracking mechanism is available, use inline generated-code segment markers at the beginning and end of each generated segment.
- If the repository policy is unclear, ask the user before choosing the mechanism.

Before finalizing a change, classify it as one of:
- Primarily or entirely AI generated.
- Assisted by AI with substantial human contribution.

Only use the following commit trailers when commit-message attribution is the selected mechanism.

For primarily or entirely AI-generated changes, add this trailer to the commit message:
```
Generated-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

For AI-assisted changes with substantial human contribution, add this trailer to the commit message:
```
Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]
```

When using `Assisted-by`, briefly describe the human vs. AI contribution in the commit body when reasonably possible. Do not fabricate model versions, agent names, or tool usage. If a value is unavailable, use the most specific known value and omit unknown optional tools.

Do not paste third-party code or snippets. Run the repository's configured software composition analysis or snippet-detection tool before finalizing when such a tool is available. If no approved SCA tool is configured in the workspace, say that explicitly in the final response or commit notes instead of inventing a tool result.

## Registry-First Workflow (MANDATORY)

Every time the user asks you to build something, follow this exact sequence:

### Step 1: Search for a page template FIRST
```bash
bun run shadcn:nitro -- search @nitro --query "<keyword matching user request>"
```
Look for `registry:block` items — these are complete page templates. Examples:
- User says "welcome page" → search "welcome" → find `welcome-page`
- User says "dashboard" → search "dashboard" → find `dashboard-page`, `dashboard-landing-page`
- User says "data management" → search "data" → find `data-management-page`
- User says "task board" → search "task" → find `task-board-page`, `task-detail-page`
- User says "chat" → search "chat" → find `chat-container`, `chat-card`, `chat-input`
- User says "search" → search "search" → find `smart-search-page`

### Step 2: Inspect the selected registry item
```bash
bun run shadcn:nitro -- view @nitro/<page-template-name>
```
Read the Nitro registry metadata from `meta.nitro` in the `view` output. Use `meta.nitro.exportName`, `meta.nitro.sourcePath`, `meta.nitro.specPath`, and `meta.nitro.requirementsPath` from the `view` output. Registry paths are package-relative and point into the generated `dist/context/` artifact: read `meta.nitro.sourcePath`, `meta.nitro.specPath`, and `meta.nitro.requirementsPath` under `node_modules/@idp/nitro-redwood/`. Read the matching generated package context source and `SPEC.md` / `REQUIREMENTS.md` before implementation. When `meta.nitro.slotRecommendations` is present, use those Nitro components for consumer-owned slots such as `main` and `infoSlot`. When `meta.nitro.scaffoldRecommendations` is present, apply its `page` values to `usePage()` and its `templateProps` values to the package template props unless the user asks for a different composition.

### Step 3: Create the route and import the template
```bash
nitro-cli page <name> --route <path> --label <label>
```
The generated page file contains `// @nitro-page-template: pending`. You MUST resolve this.

Edit the page file:
1. Update the directive to the template name: `// @nitro-page-template: welcome-page`
2. Import the canonical export from the package:
```tsx
import { <ExportName> } from '@idp/nitro-redwood';
```
3. Render the package template directly, or create an app-local wrapper/composition when customization is needed.
4. Run `nitro-cli verify` — it will FAIL if the directive is still `pending`

### Step 4: Search for additional components
If the page needs components beyond what the template provides, search and inspect again:
```bash
bun run shadcn:nitro -- search @nitro --query "<what you need>"
bun run shadcn:nitro -- view @nitro/<component-name>
```
Import matching package exports from `@idp/nitro-redwood`. Create app-local wrappers, adapters, or compositions in `src/components/` only for app-specific behavior.

### Step 5: Hand-code ONLY what's missing
After exhausting the registry, you may hand-code custom business logic, data fetching, and glue code.
But UI elements (buttons, inputs, cards, dialogs, layouts, forms) should come from `@idp/nitro-redwood` package exports when they exist.

If no page template matched, update the directive with your search terms and reason:
```
// @nitro-page-template: none — searched "welcome", "landing", "onboarding" — no template for custom animated split-panel layout
```

## Source-Copy Escape Hatch / Eject Source

Package imports are the default. Use source-copy only when `@idp/nitro-redwood` plus wrapping or composition cannot satisfy the request.

Before ejecting source:
1. Document why package import and local composition are insufficient.
2. Get explicit user approval.
3. Run:
```bash
bun run shadcn:nitro -- add @nitro/<item>
```
4. Treat copied source as app-owned code with local tests and maintenance.

## @nitro-page-template Directive (ENFORCED)

Every page file MUST have this directive. `nitro-cli verify` enforces it:

| Directive | Verify result |
|-----------|---------------|
| Missing | **FAIL** — add a directive |
| `pending` | **FAIL** — search the registry and resolve |
| `<template-name>` | **PASS** — package imports from `@idp/nitro-redwood` are valid |
| `none — <search terms> — <reason>` | **PASS** — conscious opt-out documented |

## Available Skills

Check `.agents/skills/` for Nitro-specific skills. Key skills:

| Skill | When to use |
|-------|-------------|
| `nitro-app-bootstrap` | Scaffolding a new app or understanding the scaffold structure |
| `nitro-component-discovery` | Finding package exports for UI components (forms, tables, charts, pages) |
| `nitro-page-authoring` | Creating new route pages |
| `nitro-pack-installer` | Installing pre-built page packs |
| `nitro-app-doctor` | Diagnosing setup or configuration issues |

## Commands

| Command | Description |
|---------|-------------|
| `nitro-cli verify` | Verify app definition is in sync |
| `nitro-cli doctor` | Check workspace health |
| `nitro-cli page <name>` | Create a new route page |
| `nitro-cli page <name> --force` | Overwrite an existing route (e.g. replace default home) |
| `nitro-cli add <pack>` | Install a Nitro pack |
| `bun run dev` | Start Vite dev server (port 5200) |
| `bun run build` | Production build |

> **Tip**: The default scaffold creates a `HomePage` at `/`. To replace it (e.g. with a welcome page), use `nitro-cli page welcome --route / --label Welcome --force`. The old page file is cleaned up automatically.

## Component Discovery And Usage

To use Nitro components:

1. Search with `bun run shadcn:nitro -- search @nitro --query "<keywords>"`
2. Inspect an item with `bun run shadcn:nitro -- view @nitro/<component-name>`
3. Import with `import { <ExportName> } from '@idp/nitro-redwood'`
4. Wrap or compose locally in app source when the requested behavior needs app-specific glue

The scaffolded `components.json` already points `@nitro` at https://nitro.oraclecorp.com/docs/r/{name}.json, so the shadcn CLI can search and view directly from the app root. The `shadcn:nitro` script remains available for the explicit source-copy escape hatch.

## Styling Overrides

Never edit `node_modules/@idp/nitro-redwood`, package CSS, or copied package files for styling fixes.
Keep all styling overrides app-owned and as narrow as the requested scope allows.

Use this order:

1. Prefer supported props, slots, CSS variables, and documented Nitro tokens.
2. For one page or one app-owned composition, use a co-located CSS module such as
   `src/pages/<PageName>.module.css` or `src/components/<ComponentName>/<ComponentName>.module.css`,
   scoped through a wrapper class.
3. For styling that must affect every current and future instance of a Nitro Redwood component,
   create `src/styles/nitro-overrides/<component-name>.css` and import it from
   `src/styles/globals.css` after `@idp/nitro-redwood/nitro.css`. Keep `globals.css` as the import
   hub, not the place for substantial component-specific rules.
4. Use `src/styles/shell.css` only for generated shell/layout overrides.
5. Use an app-local React wrapper when the change is behavioral, compositional, or requires default
   props. Do not rely on wrappers for app-wide style-only changes that must affect future
   registry-authored pages, because those pages may import directly from `@idp/nitro-redwood`.

When an app-wide override has no stable token or documented selector, use the narrowest practical
Nitro emitted selector and add a short comment explaining why.

### Key Page Templates (registry:block)
`welcome-page`, `dashboard-page`, `dashboard-landing-page`,
`data-management-page`, `data-authoring-page`, `home-page`, `task-board-page`,
`to-do-list-page`, `item-overview-page`, `smart-search-page`, `collection-detail-page`,
`general-overview-page`, `about-page`, `basic-page`,
`canvas-page`, `agent-monitor-page`, `epic-planner-page`, `visual-space-page`,
`memory-explorer-page`, `dynamic-foldout-page`

### Key UI Components (registry:ui)
`input`, `select`, `checkbox`, `textarea`, `radio-group`, `form-layout`, `button`,
`label`, `switch`, `combobox`, `icon`, `avatar`, `badge`, `card`, `dialog`,
`separator`, `input-password`, `input-date-picker`

## Architecture

- `src/app/definition.ts` — Generated route definitions (DO NOT edit manually)
- `src/app/router.tsx` — TanStack Router with AskOracle shell layout
- `src/main.tsx` — App entry point with NitroProviders
- `src/pages/` — Route page components
- `src/components/` — App-owned wrappers, adapters, and compositions
- `.nitro/app.json` — Project state (routes, installed packs)
- `components.json` — shadcn registry URL for @nitro components
## When Stuck

- Browser state unclear: use `bunx cdp-cli tabs`, `bunx cdp-cli snapshot <page>`, `bunx cdp-cli console <page>`, or `bunx cdp-cli network <page>` before speculative UI fixes.
- Repro needs automation: use `bunx playwright-cli open`, `bunx playwright-cli snapshot`, `bunx playwright-cli click <ref>`, and `bunx playwright-cli console`. If the browser is missing, run `bunx playwright-cli install-browser`.
- Library docs may be stale: use `bunx c7 docs <library> <topic>` before inventing APIs.
