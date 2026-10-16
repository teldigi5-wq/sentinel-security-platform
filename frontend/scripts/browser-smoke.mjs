/**
 * SENTINEL: real Chromium smoke suite with a synthetic loopback API.
 * No Playwright dependency, no access to production credentials, no network scans.
 * Requires the frontend to have been built with the normal localhost API default.
 */
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const ORIGIN = 'http://127.0.0.1:3100';
const API_PORT = 8000;
const REAL_BACKEND = process.argv.includes('--real-backend');
const fixture = REAL_BACKEND ? JSON.parse(readFileSync(process.env.SENTINEL_E2E_FIXTURE_FILE, 'utf8')) : {
  invalid: `invalid-${'x'.repeat(42)}`,
  viewer: `viewer-${'v'.repeat(42)}`,
  admin: `admin-${'a'.repeat(42)}`,
};
const now = new Date().toISOString();
const alert = {id: 'fixture-alert-01', severity: 'high', title: 'Fixture: repeated SSH failures',
  explanation: 'Synthetic UI test record', asset_id: 'fixture-host', source_ip: '192.0.2.42',
  state: 'open', rule_id: 'fixture-rule', evidence_count: 1, created_at: now};
const evt = {id: 'fixture-event-01', asset_id: 'fixture-host', sensor_id: 'fixture-sensor',
  category: 'authentication', action: 'auth_failure', source_ip: '192.0.2.42', observed_at: now};

function makeApi() {
  return createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', ORIGIN);
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    const key = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (key !== fixture.viewer && key !== fixture.admin) {
      res.writeHead(401); res.end(JSON.stringify({detail: 'Unauthorized'})); return;
    }
    const admin = key === fixture.admin;
    const path = new URL(req.url || '/', `http://127.0.0.1:${API_PORT}`).pathname;
    const routes = {
      '/api/v1/session': {operator_id: admin ? 'fixture-admin' : 'fixture-viewer',role: admin ? 'admin' : 'viewer', capabilities:{triage:admin,audit_integrity:admin}},
      '/api/v1/overview': {events:1,alerts:1,high_alerts:1,assets:1,mode:'read-only',defensive_enforcement:'not-installed'},
      '/api/v1/alerts': [alert],
      '/api/v1/events': [evt],
      '/api/v1/sensors': {stale_after_seconds:180,assurance:'synthetic-only',summary:{configured:1,healthy:1,gaps:0,explicitly_enrolled:1},sensors:[{sensor_id:'fixture-sensor',asset_id:'fixture-host',expected_asset_id:'fixture-host',binding_mode:'explicit',status:'healthy',last_seen_at:now,last_event_at:now,heartbeat_count:1,event_count:1}]},
      '/api/v1/audit/integrity': {valid:true,records:4,assurance:'synthetic-fixture'},
    };
    if (path === '/api/v1/audit/integrity' && !admin) {
      res.writeHead(403); res.end(JSON.stringify({detail:'Forbidden'})); return;
    }
    if (!Object.hasOwn(routes,path) || req.method !== 'GET') {
      res.writeHead(404); res.end(JSON.stringify({detail:'Not found'})); return;
    }
    res.writeHead(200); res.end(JSON.stringify(routes[path]));
  });
}

async function listen(server, port) {
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(port,'127.0.0.1',resolve);
  });
}
async function reachable(url) {
  try {const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),1000);
    try {return (await fetch(url,{signal:controller.signal})).ok;}finally{clearTimeout(timer);}
  } catch{return false;}
}
async function waitForReady() {
  for(let i=0;i<100;i++) {if(await reachable(ORIGIN))return;await delay(200);}
  throw new Error('Local production frontend failed to become available');
}
function detectChrome(){
  const candidates=[process.env.CHROME_BIN, '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser'].filter(Boolean);
  for(const bin of candidates){const r=spawnSync(bin,['--version'],{timeout:3000,stdio:'ignore'});if(r.status===0)return bin;}
  throw new Error('No Chromium/Google Chrome executable on runner');
}

async function connectCDP(profile) {
  const chrome=spawn(detectChrome(),['--headless=new','--no-sandbox','--disable-dev-shm-usage','--disable-gpu',
    '--disable-background-networking','--disable-extensions','--no-first-run','--no-default-browser-check',
    '--no-proxy-server','--remote-debugging-port=0',`--user-data-dir=${profile}`,'about:blank'],{stdio:'ignore'});
  let port=null;
  for(let i=0;i<100;i++){
    if(chrome.exitCode!==null)break;
    try {const text=await readFile(join(profile,'DevToolsActivePort'),'utf8');const value=Number(text.split('\n')[0]);if(value>0&&value<65536){port=value;break;}}catch{}
    await delay(100);
  }
  if(!port){chrome.kill('SIGKILL');throw new Error('Chromium debugging endpoint unavailable');}
  const targets=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const page=targets.find(t=>t.type==='page'&&t.webSocketDebuggerUrl);
  if(!page){chrome.kill('SIGKILL');throw new Error('Chromium page target unavailable');}
  const ws=new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true});});
  let id=0;const pending=new Map();
  ws.addEventListener('message',e=>{
    let data;try{data=JSON.parse(e.data);}catch{return;}
    const p=pending.get(data.id);if(!p)return;pending.delete(data.id);
    if(data.error)p.reject(new Error(`CDP error: ${data.error.message}`));else p.resolve(data.result);
  });
  const send=(method,params={})=>new Promise((resolve,reject)=>{
    if(ws.readyState!==WebSocket.OPEN)return reject(new Error('Browser connection closed'));
    const seq=++id;const t=setTimeout(()=>{pending.delete(seq);reject(new Error(`Browser ${method} timeout`));},20000);
    pending.set(seq,{resolve:v=>{clearTimeout(t);resolve(v);},reject:e=>{clearTimeout(t);reject(e);}});
    ws.send(JSON.stringify({id:seq,method,params}));
  });
  const evaluate=async expression=>{
    const result=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
    if(result.exceptionDetails)throw new Error(`Browser assertion failed: ${result.exceptionDetails.text}`);
    return result.result?.value;
  };
  return {chrome,ws,send,evaluate,close:async()=>{ws.close();if(chrome.exitCode===null){chrome.kill('SIGKILL');await Promise.race([new Promise(resolve=>chrome.once('exit',resolve)),delay(1500)]);}}};
}

const wait=`async function until(test,reason){for(let i=0;i<100;i++){if(test())return;await new Promise(r=>setTimeout(r,100));}throw new Error(reason);}`;
function loginExpression(token){return `(async()=>{${wait}
  await until(()=>document.querySelector('#operator-token')&&document.querySelector('form'),'login form missing');
  const input=document.querySelector('#operator-token');
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,${JSON.stringify(token)});
  input.dispatchEvent(new Event('input',{bubbles:true}));
  await until(()=>!document.querySelector('button[type="submit"]').disabled,'submit button disabled');
  document.querySelector('form').requestSubmit();
  return true;
})()`;}
async function phase(name,fn){await fn();console.log(`PASS: ${name}`);}

async function exerciseBrowser() {
  const api=REAL_BACKEND?null:makeApi();let next=null;let browser=null;let tmp=null;
  try {
    if(api)await listen(api,API_PORT);
    next=spawn('npm',['run','start','--','-p','3100','-H','127.0.0.1'],
      {cwd:process.cwd(),env:{...process.env,NEXT_TELEMETRY_DISABLED:'1'},detached:true,stdio:'ignore'});
    await waitForReady();
    tmp=await mkdtemp(join(tmpdir(),'sentinel-browser-fixture-'));
    browser=await connectCDP(tmp);
    await browser.send('Page.enable');await browser.send('Runtime.enable');
    await browser.send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
    await browser.send('Page.navigate',{url:ORIGIN});await delay(650);
    await phase('Unauthenticated accessible form',async()=>{
      const x=await browser.evaluate(`(async()=>{${wait}
        await until(()=>document.querySelector('#operator-token'),'login screen unavailable');
        const input=document.querySelector('#operator-token');
        return {type:input.type,label:document.querySelector('label[for="operator-token"]')?.textContent,stored:localStorage.length+sessionStorage.length};
      })()`);
      assert.equal(x.type,'password');assert.match(x.label,/Operator credential/);assert.equal(x.stored,0);
    });
    await phase('Basic keyboard and form accessibility contract',async()=>{
      const state=await browser.evaluate(`(()=>{
        const field=document.querySelector('#operator-token');
        const form=field?.closest('form');
        const label=document.querySelector('label[for="operator-token"]');
        const submit=form?.querySelector('button[type="submit"]');
        return {fieldLabeled:!!label&&label.textContent.trim().length>0,
          fieldFocusable:field?.tabIndex>=0,
          submitNamed:!!submit&&submit.textContent.trim().length>0,
          mainPresent:!!document.querySelector('main')};
      })()`);
      assert(state.fieldLabeled&&state.fieldFocusable&&state.submitNamed, 'Login input accessibility contract failed');
    });
    await phase('Invalid operator credential rejected',async()=>{
      await browser.evaluate(loginExpression(fixture.invalid));
      const message=await browser.evaluate(`(async()=>{${wait}await until(()=>document.querySelector('[role="alert"]'),'missing invalid-login alert');return document.querySelector('[role="alert"]').textContent;})()`);
      assert.match(message,/Invalid operator credential/);
    });
    await phase('Viewer login and role-separated navigation',async()=>{
      await browser.evaluate(loginExpression(fixture.viewer));
      const state=await browser.evaluate(`(async()=>{${wait}
        await until(()=>document.querySelector('nav[aria-label="Main navigation"]'),'dashboard missing');
        await until(()=>document.querySelector('.metric-grid strong')?.textContent===String(${fixture.expectedEvents??1}),'synthetic counters missing');
        const labels=[...document.querySelectorAll('nav button')].map(b=>b.textContent.trim());
        return {labels,metrics:[...document.querySelectorAll('.metric-grid strong')].map(x=>x.textContent),storage:[...Object.values(localStorage),...Object.values(sessionStorage)]};
      })()`);
      assert(state.labels.includes('Event intelligence'));assert(!state.labels.includes('Evidence integrity'));
      assert.equal(state.metrics[0],String(fixture.expectedEvents??1));assert.deepEqual(state.storage,[]);
    });
    await phase('Navigation renders signed fixture event and role-limited UI',async()=>{
      const x=await browser.evaluate(`(async()=>{${wait}
        const button=[...document.querySelectorAll('nav button')].find(b=>b.textContent.includes('Event intelligence'));
        button.click();await until(()=>document.querySelector('h1')?.textContent==='Event intelligence','event tab missing');
        const activePage=button.getAttribute('aria-current');
        return {activePage,eventVisible:document.body.textContent.includes('fixture-host'),table:!!document.querySelector('table'),triage:!!document.querySelector('textarea')};
      })()`);
      assert.equal(x.activePage,'page');assert.equal(x.eventVisible,true);assert.equal(x.table,true);assert.equal(x.triage,false);
    });
    if(REAL_BACKEND)await phase('Real evidence links resolve through authenticated API',async()=>{
      const actual=await browser.evaluate(`(async()=>{${wait}
        const tab=[...document.querySelectorAll('nav button')].find(b=>b.textContent.includes('Alert intelligence')||b.textContent.includes('Alert register')||b.textContent.includes('Detection register'));
        const actualTab=tab || [...document.querySelectorAll('nav button')].find(b=>b.textContent.trim()==='Investigations');
        if(!actualTab)throw new Error('Alert navigation missing');
        actualTab.click();
        await until(()=>document.querySelector('button[aria-label^="Review evidence for"]'),'Real backend alert missing');
        document.querySelector('button[aria-label^="Review evidence for"]').click();
        await until(()=>document.querySelectorAll('.evidence-row').length===5,'Real signed evidence links missing');
        return {count:document.querySelectorAll('.evidence-row').length,readonly:!document.querySelector('#triage-reason')};
      })()`);
      assert.equal(actual.count,fixture.expectedAlertEvidence);assert(actual.readonly);
    });
    await phase('Mobile viewport, navigable drawer and no page overflow',async()=>{ 
      await browser.send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
      const x=await browser.evaluate(`(async()=>{${wait}
        await until(()=>getComputedStyle(document.querySelector('.mobile-menu')).display!=='none','mobile menu missing');
        document.querySelector('.mobile-menu').click();
        await until(()=>document.querySelector('.sidebar').classList.contains('sidebar-open'),'navigation drawer did not open');
        const open=document.querySelector('.sidebar').classList.contains('sidebar-open');
        const expandedOpen=document.querySelector('.mobile-menu').getAttribute('aria-expanded');
        document.querySelector('.mobile-overlay').click();
        await until(()=>!document.querySelector('.sidebar').classList.contains('sidebar-open'),'navigation drawer did not close');
        return {open,expandedOpen,expandedClosed:document.querySelector('.mobile-menu').getAttribute('aria-expanded'),width:innerWidth,scrollWidth:document.documentElement.scrollWidth,navLabel:document.querySelector('.mobile-menu').getAttribute('aria-label')};
      })()`);
      assert(x.open);assert.equal(x.expandedOpen,'true');assert.equal(x.expandedClosed,'false');assert(x.scrollWidth<=x.width+3,`Unexpected horizontal page overflow: ${x.scrollWidth} / ${x.width}`);
      assert.equal(x.navLabel,'Toggle navigation');
    });
    await phase('Sign-out removes dashboard and memory-only token',async()=>{
      const x=await browser.evaluate(`(async()=>{${wait}
        document.querySelector('.signout').click();
        await until(()=>!!document.querySelector('#operator-token'),'sign-out did not return to login');
        return {login:!!document.querySelector('#operator-token'),nav:!!document.querySelector('nav'),stored:localStorage.length+sessionStorage.length};
      })()`);
      assert(x.login&&!x.nav);assert.equal(x.stored,0);
    });
    await phase('Administrator-only integrity tab',async()=>{
      await browser.send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
      await browser.evaluate(loginExpression(fixture.admin));
      const state=await browser.evaluate(`(async()=>{${wait}
        await until(()=>document.querySelector('nav[aria-label="Main navigation"]'),'admin dashboard missing');
        const button=[...document.querySelectorAll('nav button')].find(b=>b.textContent.includes('Evidence integrity'));
        if(!button)throw new Error('admin integrity tab missing');button.click();
        await until(()=>document.querySelector('.integrity-surface h2'),'integrity detail missing');
        return {heading:document.querySelector('.integrity-surface h2').textContent,records:document.querySelector('.integrity-stats')?.textContent};
      })()`);
      assert.match(state.heading,/Local chain verified/);assert.match(state.records,new RegExp(String(fixture.expectedAuditRecords??4)));
    });
    console.log(REAL_BACKEND?'PASS: browser suite completed (real Chromium and real synthetic-seeded FastAPI)': 'PASS: browser suite completed (real Chromium, synthetic localhost data only)');
  } finally {
    if(browser)await browser.close().catch(()=>{});
    if(next?.pid){try{process.kill(-next.pid,'SIGKILL');}catch{next.kill('SIGKILL');}}
    if(api)await new Promise(resolve=>api.close(resolve));
    if(tmp)await rm(tmp,{recursive:true,force:true,maxRetries:8,retryDelay:100});
  }
}

if(process.argv.includes('--self-test')) {
  // Only the Chrome DevTools Protocol transport is tested locally. Managed
  // container browser policy may block all navigation, including localhost.
  let browser,tmp;
  try {
    tmp=await mkdtemp(join(tmpdir(),'sentinel-cdp-selftest-'));
    browser=await connectCDP(tmp);
    await browser.send('Page.enable');await browser.send('Runtime.enable');
    const observed=await browser.evaluate(`(()=>{document.body.innerHTML='<main id="test">ready</main>';return document.querySelector('#test').textContent;})()`);
    assert.equal(observed,'ready');
    console.log('PASS: Chrome DevTools Protocol transport only (not dashboard UI)');
  } finally {
    if(browser)await browser.close().catch(()=>{});
    if(tmp)await rm(tmp,{recursive:true,force:true,maxRetries:8,retryDelay:100});
  }
} else {
  exerciseBrowser().catch(()=>{
    console.error('FAIL: Chromium dashboard smoke qualification (inspect job results; no production data used)');
    process.exitCode=1;
  });
}