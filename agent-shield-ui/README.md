# Agent Shield UI

Nitro-first frontend for a future dependency-analysis agent with two result areas:

- CVE detection
- open-source license checks

The backend is not connected yet. The Analyze button and result sections are UI
placeholders ready for later API integration.

## Run locally

In powershell :

```
& "$env:USERPROFILE\.bun\bin\bun.exe" install
& "$env:USERPROFILE\.bun\bin\bun.exe" run dev
```

In Git Bash :

Open Git Bash in this folder and run:

```bash
export PATH="/c/Users/Mounika/.bun/bin:$PATH"
bun install
bun run dev
```

Then open `http://localhost:5200`.

Stop the app with `Ctrl+C` in the same terminal.
