import fs from 'node:fs'
import path from 'node:path'
import Database from 'better-sqlite3'
import { assetClasses, assets, scanSources } from './seedData.mjs'
import { upsertSeedData } from './repository.mjs'

const args = new Set(process.argv.slice(2))
const isReset = args.has('--reset')

const rootDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..')
const dbDir = path.join(rootDir, 'db')
const dbPath = path.join(dbDir, 'agentshield.sqlite')
const schemaPath = path.join(dbDir, 'schema.sql')

fs.mkdirSync(dbDir, { recursive: true })

if (isReset && fs.existsSync(dbPath)) {
  fs.unlinkSync(dbPath)
  console.log(`Deleted existing DB: ${dbPath}`)
}

const db = new Database(dbPath)
db.pragma('foreign_keys = ON')

const schemaSql = fs.readFileSync(schemaPath, 'utf8')
db.exec(schemaSql)

upsertSeedData(db, { assetClasses, scanSources, assets })

const counts = {
  assetClasses: db.prepare('SELECT COUNT(*) AS value FROM asset_classes').get().value,
  assets: db.prepare('SELECT COUNT(*) AS value FROM assets').get().value,
  scanSources: db.prepare('SELECT COUNT(*) AS value FROM scan_sources').get().value,
  runs: db.prepare('SELECT COUNT(*) AS value FROM scan_runs').get().value,
}

db.close()

console.log(`SQLite initialized at: ${dbPath}`)
console.log(`asset_classes=${counts.assetClasses}, assets=${counts.assets}, scan_sources=${counts.scanSources}, scan_runs=${counts.runs}`)
