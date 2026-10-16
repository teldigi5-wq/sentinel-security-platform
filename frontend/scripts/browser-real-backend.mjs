/**
 * End-to-end production Next.js dashboard against actual FastAPI + SQLite + Alembic.
 * The disposable fixture is generated with signed ingestion by the Python app.
 * Nothing leaves localhost and no operator credentials are printed or uploaded.
 */
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const backend = resolve(process.cwd(), '../backend');
const API = 'http://127.0.0.1:8000/api/v1/health';

async function ready(child) {
  for (let i = 0; i < 120; i++) {
    if (child.exitCode !== null) throw new Error('Real backend quit before healthy');
    try { const controller = new AbortController(); const id = setTimeout(() => controller.abort(), 1000);
      try { const res = await fetch(API, {signal: controller.signal}); if(res.ok) return; }
      finally {clearTimeout(id);}
    } catch {}
    await delay(150);
  }
  throw new Error('Real backend not ready on loopback');
}

async function main() {
  const dir = await mkdtemp(join(tmpdir(),'sentinel-real-backend-ci-'));
  let service = null;
  try {
    const seeder = spawnSync('python',['-m','scripts.seed_browser_fixture','--directory',dir],
      {cwd:backend,encoding:'utf8',timeout:25000,env:{...process.env, PYTHONUNBUFFERED:'1'}});
    if (seeder.status !== 0) throw new Error('Real backend fixture seed failed; inspect Python tests');
    const configFile = join(dir,'fixture.json');
    const config = JSON.parse(await readFile(configFile,'utf8'));
    assert.equal(config.expectedEvents,5);
    service = spawn('python',['-m','uvicorn','sentinel.main:app','--host','127.0.0.1',
      '--port','8000','--no-access-log','--log-level','error'],
      {cwd:backend,env:{...process.env,...config.env},detached:true,stdio:'ignore'});
    await ready(service);
    const smoke = spawnSync('node',['scripts/browser-smoke.mjs','--real-backend'],
      {cwd:process.cwd(),env:{...process.env,SENTINEL_E2E_FIXTURE_FILE:configFile},
        encoding:'utf8',timeout:125000});
    // Browser logs contain only assertion names (never tokens or raw payloads).
    if (smoke.stdout) process.stdout.write(smoke.stdout);
    if (smoke.status !== 0) throw new Error('Real backend + browser integration failed');
    console.log('PASS: genuine FastAPI + SQLite + signed ingest + Next.js Chromium integration');
  } finally {
    if (service?.pid) {try {process.kill(-service.pid,'SIGKILL');} catch {service.kill('SIGKILL');}}
    await rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:100});
  }
}
main().catch(() => {console.error('FAIL: genuine backend/browser qualification');process.exitCode=1;});