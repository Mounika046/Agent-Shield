import fs from 'node:fs'
import path from 'node:path'
import Database from 'better-sqlite3'
import { saveScanRun } from './repository.mjs'

const runJsonPath = process.argv[2]

if (!runJsonPath) {
  console.error('Usage: npm run db:import-run -- <path-to-run-json>')
  process.exit(1)
}

const rootDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..')
const dbPath = path.join(rootDir, 'db', 'agentshield.sqlite')

if (!fs.existsSync(dbPath)) {
  console.error(`Database not found at ${dbPath}. Run "npm run db:init" first.`)
  process.exit(1)
}

const absoluteRunPath = path.resolve(process.cwd(), runJsonPath)
const run = JSON.parse(fs.readFileSync(absoluteRunPath, 'utf8'))

const db = new Database(dbPath)
db.pragma('foreign_keys = ON')

saveScanRun(db, run)

const counts = {
  runs: db.prepare('SELECT COUNT(*) AS value FROM scan_runs').get().value,
  findings: db.prepare('SELECT COUNT(*) AS value FROM cve_findings').get().value,
}

db.close()

console.log(`Imported run ${run.id} into SQLite DB.`)
console.log(`scan_runs=${counts.runs}, cve_findings=${counts.findings}`)
