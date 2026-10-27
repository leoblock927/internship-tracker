// Internship Tracker. A static page that reads and writes JSON files in a private GitHub repo.
// No data is stored on this site: everything loads through the GitHub API. The GitHub token is kept on each
// device encrypted with your password (PBKDF2 + AES-GCM), and only decrypted in memory for the open tab.
'use strict';

const CFG = { owner: 'leoblock927', repo: 'internship-pipeline', branch: 'main', scanWorkflow: 'daily-scan.yml', detectWorkflow: 'detect-boards.yml' };
const FILES = {
  applications: 'data/applications.json',
  waiting: 'data/waiting.json',
  pipeline: 'data/pipeline.json',
  status: 'data/pipeline-status.json',
  control: 'data/control.json',
  options: 'data/options.json',
  lastRun: 'data/last-run.json',
  resume: 'config/resume.json',
  packetReq: 'data/packet-requests.json',
};
const packetName = id => `${String(id).replace(/[^a-z0-9]+/gi, '_').slice(0, 120)}.json`;
const ENC_KEY = 'tracker.enc.v1';        // localStorage: encrypted token
const SESSION_KEY = 'tracker.session.v1'; // sessionStorage: token for this tab only
const PREF_KEY = 'tracker.prefs.v1';
const DEMO = new URLSearchParams(location.search).has('demo');

const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const safeUrl = u => (/^https?:\/\//i.test(String(u || '')) ? String(u) : '');
const today = () => { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
const uid = p => `${p}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`;
const norm = s => String(s || '').toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, ' ').trim();

function loadPrefs() { try { return JSON.parse(localStorage.getItem(PREF_KEY)) || {}; } catch { return {}; } }
function savePrefs() { try { localStorage.setItem(PREF_KEY, JSON.stringify(S.prefs)); } catch { /* private mode */ } }
const store = {
  get: (k, ss) => { try { return (ss ? sessionStorage : localStorage).getItem(k) || ''; } catch { return ''; } },
  set: (k, v, ss) => { try { const s = ss ? sessionStorage : localStorage; v ? s.setItem(k, v) : s.removeItem(k); } catch { /* private mode */ } },
};

/* ---------- password encryption for the token ---------- */
const b64u = {
  enc: buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: str => Uint8Array.from(atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4)), c => c.charCodeAt(0)),
};
async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function sealToken(token, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await deriveKey(password, salt), new TextEncoder().encode(token));
  return `v1.${b64u.enc(salt)}.${b64u.enc(iv)}.${b64u.enc(ct)}`;
}
async function openToken(blob, password) {
  const [v, s, i, c] = String(blob).split('.');
  if (v !== 'v1' || !c) throw new Error('That setup link is damaged. Make a new one.');
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64u.dec(i) }, await deriveKey(password, b64u.dec(s)), b64u.dec(c));
    return new TextDecoder().decode(pt);
  } catch { throw new Error('Wrong password.'); }
}

const S = {
  token: store.get(SESSION_KEY, true),
  data: {},
  view: 'pipeline',
  prefs: { pipeFilter: 'New', appFilter: 'In Progress', appSort: ['dateApplied', -1], ...loadPrefs() },
  q: '',
  runs: [],
  polling: null,
};

/* ---------- utf-8 safe base64 ---------- */
function b64encode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}
function b64decode(b64) {
  const bin = atob(b64.replace(/\s/g, ''));
  return new TextDecoder().decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
}

/* ---------- GitHub API ---------- */
async function gh(path, opts = {}) {
  const res = await fetch(`https://api.github.com${path}`, {
    ...opts,
    cache: 'no-store',
    headers: {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      Authorization: `Bearer ${S.token}`,
      ...(opts.body ? { 'Content-Type': 'application/json' } : {}),
      ...(opts.headers || {}),
    },
  });
  if (res.status === 401) { lock('GitHub rejected the saved token. It may have expired; make a new one.'); throw new Error('Unauthorized'); }
  return res;
}
const repoPath = p => `/repos/${CFG.owner}/${CFG.repo}${p}`;

async function readFile(path) {
  if (DEMO) return demoRead(path);
  const res = await gh(repoPath(`/contents/${path}?ref=${CFG.branch}&t=${Date.now()}`));
  if (res.status === 404) return { data: null, sha: null };
  if (!res.ok) throw new Error(`Read ${path}: ${res.status}`);
  const j = await res.json();
  return { data: JSON.parse(b64decode(j.content)), sha: j.sha };
}

// Read the latest copy, apply the change, write it back. Retries if someone else wrote in between.
async function updateFile(path, mutate, message) {
  if (DEMO) return demoUpdate(path, mutate);
  for (let attempt = 0; attempt < 4; attempt++) {
    const { data, sha } = await readFile(path);
    const next = mutate(structuredClone(data ?? {}));
    const res = await gh(repoPath(`/contents/${path}`), {
      method: 'PUT',
      body: JSON.stringify({ message, content: b64encode(JSON.stringify(next, null, 1) + '\n'), branch: CFG.branch, ...(sha ? { sha } : {}) }),
    });
    if (res.ok) return next;
    if (res.status === 409 || res.status === 422) { await sleep(400 * (attempt + 1)); continue; }
    throw new Error(`Save ${path}: ${res.status} ${(await res.text()).slice(0, 140)}`);
  }
  throw new Error(`Save ${path}: kept colliding with another edit. Refresh and try again.`);
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function dispatch(workflow, inputs) {
  if (DEMO) { toast('Demo mode: a real run would start now.'); return; }
  const res = await gh(repoPath(`/actions/workflows/${workflow}/dispatches`), { method: 'POST', body: JSON.stringify({ ref: CFG.branch, inputs }) });
  if (res.status !== 204) throw new Error(`Couldn't start the run (${res.status}). The token needs Actions: Read and write.`);
}

async function listPackets() {
  S.packetCache ||= {};
  if (DEMO) { S.packets = new Set(Object.keys(DEMO_PACKETS)); return; }
  try {
    const res = await gh(repoPath(`/contents/data/packets?ref=${CFG.branch}&t=${Date.now()}`));
    if (!res.ok) { S.packets = new Set(); return; }
    const list = await res.json();
    S.packets = new Set(list.filter(f => f.name.endsWith('.json')).map(f => f.name));
    // Drop cached packets whose file changed (rebuilt).
    for (const f of list) if (S.packetCache[f.name] && S.packetCache[f.name]._sha !== f.sha) delete S.packetCache[f.name];
    S.packetShas = Object.fromEntries(list.map(f => [f.name, f.sha]));
  } catch { S.packets = new Set(); }
}
async function getPacket(id) {
  const name = packetName(id);
  if (S.packetCache[name]) return S.packetCache[name];
  const { data } = DEMO ? { data: structuredClone(DEMO_PACKETS[name]) } : await readFile(`data/packets/${name}`);
  if (data) { data._sha = S.packetShas?.[name]; S.packetCache[name] = data; }
  return data;
}

async function loadRuns() {
  if (DEMO) { S.runs = []; return; }
  try {
    const res = await gh(repoPath('/actions/runs?per_page=6'));
    if (!res.ok) return;
    S.runs = (await res.json()).workflow_runs || [];
  } catch { /* non-fatal */ }
}

/* ---------- loading ---------- */
async function loadAll() {
  setFoot('Loading...');
  const entries = await Promise.all(Object.entries(FILES).map(async ([k, path]) => [k, (await readFile(path)).data]));
  for (const [k, v] of entries) S.data[k] = v;
  S.data.applications ??= { items: [] };
  S.data.waiting ??= { items: [] };
  S.data.pipeline ??= { items: [] };
  S.data.status ??= { items: {} };
  S.data.control ??= { paused: false };
  S.data.options ??= {};
  S.data.packetReq ??= { items: {} };
  await Promise.all([loadRuns(), listPackets()]);
  setFoot(`Loaded ${new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`);
  render();
  watchRuns();
}

/* ---------- lock screen ---------- */
function tokenUrl() {
  const q = new URLSearchParams({
    name: 'Internship Tracker',
    description: 'Lets the tracker site read and edit internship-pipeline data and start scans.',
    target_name: CFG.owner,
    expires_in: '366',
    contents: 'write',
    actions: 'write',
  });
  return `https://github.com/settings/personal-access-tokens/new?${q}`;
}
function showLock(mode, msg = '') {
  S.token = '';
  store.set(SESSION_KEY, '', true);
  clearTimeout(S.polling);
  $('#app').hidden = true; $('#tabs').hidden = true; $('#lockbtn').hidden = true; $('#foot').hidden = true;
  const box = $('#lock');
  box.hidden = false;
  const err = `<div class="err-text" id="lockerr" ${msg ? '' : 'hidden'}>${esc(msg)}</div>`;
  if (mode === 'password') {
    box.innerHTML = `<h1>Internship<br>Tracker</h1>
      <p>Enter your tracker password.</p>
      <form id="lockform" data-mode="password" autocomplete="on">
        <input type="text" name="username" value="internship-tracker" autocomplete="username" hidden>
        <input id="pw" type="password" autocomplete="current-password" placeholder="Password" aria-label="Password" required autofocus>
        <button class="btn primary" type="submit">Unlock</button>
      </form>${err}
      <p style="margin-top:16px;font-size:.88rem"><a href="#" data-act="forget">Forget this device</a> to start over with a new token.</p>`;
  } else if (mode === 'pair') {
    box.innerHTML = `<h1>Set up<br>this device</h1>
      <p>Enter your tracker password to finish. After this, this device only asks for the password.</p>
      <form id="lockform" data-mode="pair" autocomplete="on">
        <input type="text" name="username" value="internship-tracker" autocomplete="username" hidden>
        <input id="pw" type="password" autocomplete="current-password" placeholder="Password" aria-label="Password" required autofocus>
        <button class="btn primary" type="submit">Unlock</button>
      </form>${err}`;
  } else {
    box.innerHTML = `<h1>Internship<br>Tracker</h1>
      <p>This page is public, but the data isn't. It lives in a private GitHub repo and loads only with a GitHub token, which this device stores encrypted with a password you choose.</p>
      <ol>
        <li><a href="${esc(tokenUrl())}" target="_blank" rel="noopener">Create a fine-grained token</a> (opens GitHub with the settings filled in).</li>
        <li>Under Repository access pick <b>Only select repositories</b> and choose <b>internship-pipeline</b>.</li>
        <li>Check it has <b>Contents: Read and write</b> and <b>Actions: Read and write</b>, then generate it.</li>
        <li>Paste it below and pick a password. Use "Set up my phone" later to add your phone with a QR code.</li>
      </ol>
      <form id="lockform" data-mode="setup" autocomplete="on" style="display:grid;gap:8px">
        <input type="text" name="username" value="internship-tracker" autocomplete="username" hidden>
        <input id="tok" type="password" autocomplete="off" placeholder="github_pat_..." aria-label="GitHub token" required>
        <input id="pw" type="password" autocomplete="new-password" placeholder="New password (8+ characters)" minlength="8" aria-label="New password" required>
        <input id="pw2" type="password" autocomplete="new-password" placeholder="Same password again" minlength="8" aria-label="Confirm password" required>
        <button class="btn primary" type="submit">Save and unlock</button>
      </form>${err}`;
  }
  setTimeout(() => box.querySelector('input:not([hidden])')?.focus(), 30);
}
async function checkToken(token) {
  const res = await fetch(`https://api.github.com${repoPath('')}`, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
  if (res.status === 401) throw new Error('GitHub rejected that token. It may have expired; make a new one.');
  if (res.status === 404) throw new Error("That token can't see the internship-pipeline repo. Pick it under Repository access.");
  if (!res.ok) throw new Error(`GitHub said ${res.status}. Try again.`);
}
async function onLockSubmit(form) {
  const mode = form.dataset.mode;
  const pw = $('#pw').value;
  const btn = form.querySelector('button'); btn.disabled = true; btn.textContent = 'Checking...';
  try {
    let token;
    if (mode === 'setup') {
      if (pw !== $('#pw2').value) throw new Error("Those passwords don't match.");
      token = $('#tok').value.trim();
      await checkToken(token);
      store.set(ENC_KEY, await sealToken(token, pw));
    } else if (mode === 'pair') {
      const blob = S.pairBlob;
      token = await openToken(blob, pw);
      await checkToken(token);
      store.set(ENC_KEY, blob);
      S.pairBlob = null;
      history.replaceState(null, '', location.pathname + location.search + '#pipeline');
    } else {
      token = await openToken(store.get(ENC_KEY), pw);
    }
    S.token = token;
    store.set(SESSION_KEY, token, true);
    showApp();
  } catch (err) {
    const e = $('#lockerr'); e.hidden = false; e.textContent = err.message;
    btn.disabled = false; btn.textContent = mode === 'setup' ? 'Save and unlock' : 'Unlock';
  }
}
function lock(msg) {
  // A rejected token means it expired or was revoked: start over. Otherwise just ask for the password again.
  if (msg) { store.set(ENC_KEY, ''); showLock('setup', msg); }
  else showLock(store.get(ENC_KEY) ? 'password' : 'setup');
}
function showApp() {
  $('#lock').hidden = true; $('#app').hidden = false; $('#tabs').hidden = false; $('#foot').hidden = false;
  $('#lockbtn').hidden = DEMO;
  loadAll().catch(err => toast(err.message, true));
}

/* ---------- derived data ---------- */
const pipeStatus = id => S.data.status.items?.[id]?.status || 'New';
const scoreOf = j => (j.score != null ? j.score : j.heuristic);
const STAGE_WIRE = { Outreach: 'hv', Emailed: 'hv', Applied: 'auto', Screening: 'can', Assessment: 'can', Interview: 'can', 'Technical Interview': 'can', 'Final Round': 'can', Offer: 'can', Rejected: 'batt' };
const wireVar = c => (c ? `var(--${c})` : 'var(--mute)');
function appWire(a) {
  if (a.status === 'Rejected' || a.status === 'Withdrawn') return 'batt';
  if (a.status === 'Accepted') return 'can';
  return STAGE_WIRE[a.stage] || null;
}
function scoreWire(j) {
  const s = scoreOf(j) ?? 0;
  if (j.score == null) return s >= 30 ? 'can' : s >= 20 ? 'auto' : null;
  return s >= 80 ? 'can' : s >= 65 ? 'auto' : s >= 50 ? 'hv' : null;
}
function matchesQ(...fields) {
  if (!S.q) return true;
  const hay = norm(fields.join(' '));
  return norm(S.q).split(' ').every(w => hay.includes(w));
}
function guessPortal(url) {
  const u = String(url || '');
  if (/greenhouse/.test(u)) return 'Greenhouse';
  if (/lever\.co/.test(u)) return 'Lever';
  if (/ashbyhq/.test(u)) return 'Ashby';
  if (/myworkdayjobs|workday/.test(u)) return 'Workday';
  if (/icims/.test(u)) return 'iCIMS';
  return 'Other';
}
function counts() {
  const p = S.data.pipeline.items.filter(j => pipeStatus(j.id) === 'New').length;
  const a = S.data.applications.items.filter(x => x.status === 'In Progress').length;
  $('#c-pipeline').textContent = p ? ` ${p}` : '';
  const due = allDue().length;
  $('#c-applications').textContent = ` ${a}${due ? ` · ${due} due` : ''}`;
  $('#c-waiting').textContent = ` ${S.data.waiting.items.length}`;
}

/* ---------- rendering ---------- */
function render() {
  document.querySelectorAll('#tabs button').forEach(b => b.setAttribute('aria-current', b.dataset.view === S.view ? 'page' : 'false'));
  renderTitleBlock();
  counts();
  const v = $('#view');
  if (S.view === 'pipeline') v.innerHTML = viewPipeline();
  else if (S.view === 'applications') v.innerHTML = viewApplications();
  else if (S.view === 'waiting') v.innerHTML = viewWaiting();
  else v.innerHTML = viewSummary();
  const s = $('#search');
  if (s && document.activeElement !== s) { s.value = S.q; }
}

function renderTitleBlock() {
  const paused = !!S.data.control?.paused;
  const active = S.runs.find(r => r.status !== 'completed');
  const st = $('#scanstate');
  if (active) {
    const label = { 'Daily internship scan': 'Scan', 'Detect job boards': 'Detecting boards', 'Build application packets': 'Building packets' }[active.name] || active.name;
    st.className = 'state busy'; st.textContent = `${label} ${active.status === 'queued' ? 'queued' : 'running'}`;
  }
  else if (paused) { st.className = 'state paused'; st.textContent = 'Paused'; }
  else { st.className = 'state on'; st.textContent = 'Active'; }
  const pb = $('#pausebtn');
  pb.textContent = paused ? 'Resume' : 'Pause';
  pb.className = `btn ${paused ? 'go' : 'warn'}`;

  const lr = S.data.lastRun;
  const lastScan = S.runs.find(r => r.path?.endsWith(CFG.scanWorkflow) && r.status === 'completed');
  if (lr) {
    const when = lr.finishedAt ? new Date(lr.finishedAt) : null;
    const failed = lastScan && lastScan.conclusion !== 'success';
    $('#lastrun').innerHTML = `${esc(when ? when.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ', ' + when.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : lr.date)}<small>${failed ? '<span style="color:var(--batt)">last run failed</span>' : esc(lr.mode === 'paused' ? 'skipped (paused)' : (lr.trigger === 'schedule' ? 'scheduled' : 'manual'))}</small>`;
    const s = lr.stats || {};
    $('#lastfound').innerHTML = lr.mode === 'paused' ? '<small>nothing, paused</small>' : `${esc(lr.added ?? 0)} added<small>of ${esc(s.new ?? 0)} new, ${esc((s.fetched ?? 0).toLocaleString())} checked${lr.errors?.length ? `, <span style="color:var(--batt)">${lr.errors.length} errors</span>` : ''}</small>`;
  } else {
    $('#lastrun').innerHTML = '<small>No runs yet</small>';
    $('#lastfound').innerHTML = '<small>...</small>';
  }
}

function toolbar(title, sub, extra = '') {
  return `<div class="toolbar"><h2>${esc(title)}<small>${esc(sub)}</small></h2>
    <input class="search" id="search" type="search" placeholder="Search" value="${esc(S.q)}" aria-label="Search">${extra}</div>`;
}
function seg(key, values, countFn) {
  return `<div class="seg" role="group">${values.map(v => {
    const c = countFn ? countFn(v) : null;
    return `<button type="button" data-act="seg" data-key="${key}" data-val="${esc(v)}" aria-pressed="${S.prefs[key] === v}">${esc(v)}${c ? ` <span class="segn">${c}</span>` : ''}</button>`;
  }).join('')}</div>`;
}

function viewPipeline() {
  const all = S.data.pipeline.items;
  const f = S.prefs.pipeFilter;
  const list = all
    .filter(j => f === 'All' || pipeStatus(j.id) === f)
    .filter(j => matchesQ(j.company, j.title, (j.locations || []).join(' '), (j.flags || []).join(' ')))
    .sort((a, b) => (b.dateFound || '').localeCompare(a.dateFound || '') || (scoreOf(b) ?? 0) - (scoreOf(a) ?? 0));
  const n = s => all.filter(j => pipeStatus(j.id) === s).length;
  const head = toolbar('Pipeline', `${n('New')} new, ${n('Approved')} approved`, seg('pipeFilter', ['New', 'Approved', 'Applied', 'Skipped', 'All'], v => (v === 'All' ? 0 : n(v))));
  if (!list.length) return head + `<div class="empty">${f === 'New' ? 'No new matches right now. The next scan runs tomorrow morning, or press Run scan.' : 'Nothing here.'}</div>`;
  return head + `<div class="cards">${list.map(pipeCard).join('')}</div>`;
}
function pipeCard(j) {
  const st = pipeStatus(j.id);
  const url = safeUrl(j.url);
  const sc = scoreOf(j);
  const flags = (j.flags || []).map(f => `<span class="chip ${/defense/.test(f) ? 'hv' : /clearance|differs/.test(f) ? 'batt' : ''}">${esc(f)}</span>`).join('');
  const terms = (j.terms || []).map(t => `<span class="chip">${esc(t)}</span>`).join('');
  const stChip = st !== 'New' ? `<span class="chip ${st === 'Approved' ? 'can' : st === 'Applied' ? 'auto' : ''}">${esc(st)}</span>` : '';
  const hasPacket = S.packets?.has(packetName(j.id));
  const building = !hasPacket && st === 'Approved' && S.runs.some(r => r.name === 'Build application packets' && r.status !== 'completed');
  const packetChip = st === 'Approved' && !hasPacket ? `<span class="chip">${building ? 'building packet...' : 'packet pending'}</span>` : '';
  const packetBtn = hasPacket ? `<button class="btn small" data-act="packet-open" data-id="${esc(j.id)}">Open packet</button>` : '';
  const acts = st === 'New'
    ? `<button class="btn small go" data-act="pipe-approve" data-id="${esc(j.id)}">Approve</button>
       <button class="btn small" data-act="pipe-applied" data-id="${esc(j.id)}">Applied</button>
       <button class="btn small" data-act="pipe-skip" data-id="${esc(j.id)}">Skip</button>`
    : st === 'Approved'
      ? `${packetBtn}<button class="btn small primary" data-act="pipe-applied" data-id="${esc(j.id)}">Mark applied</button>
         <button class="btn small" data-act="pipe-undo" data-id="${esc(j.id)}">Undo</button>`
      : `${packetBtn}<button class="btn small" data-act="pipe-undo" data-id="${esc(j.id)}">Move back to New</button>`;
  return `<article class="card" style="--wire:${wireVar(scoreWire(j))}">
    <div class="score">${sc == null ? '-' : (j.score == null ? '~' : '') + esc(sc)}<small>${j.score == null ? 'keyword' : 'fit'}</small></div>
    <div>
      <h3>${url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(j.title)}</a>` : esc(j.title)}</h3>
      <div class="meta"><b>${esc(j.company)}</b> · ${esc((j.locations || []).slice(0, 2).join('; ') || 'Location not listed')} · found ${esc(j.dateFound || '')}</div>
      ${(j.reasons || []).length ? `<ul class="reasons">${j.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      <div class="chips">${stChip}${packetChip}${terms}${flags}</div>
    </div>
    <div class="acts">${acts}</div>
  </article>`;
}

const APP_COLS = [
  ['company', 'Company'], ['role', 'Role'], ['stage', 'Stage'], ['status', 'Status'], ['dateApplied', 'Applied'],
  ['location', 'Location'], ['contact', 'Contact'], ['nextStep', 'Next step'], ['notes', 'Notes'],
];
function viewApplications() {
  const items = S.data.applications.items;
  const f = S.prefs.appFilter;
  const [sk, dir] = S.prefs.appSort;
  const list = items
    .filter(a => f === 'All' || (f === 'Follow up' ? a.status === 'In Progress' && (!!a.nextStep || dueOutreach(a).length > 0) : a.status === f))
    .filter(a => matchesQ(a.company, a.role, a.stage, a.status, a.location, a.contact, a.notes, a.nextStep, a.industry, a.source))
    .sort((a, b) => dir * String(a[sk] || '').localeCompare(String(b[sk] || ''), undefined, { numeric: true }) || String(b.dateApplied).localeCompare(String(a.dateApplied)));
  const head = toolbar('Applications', `${items.length} total, ${items.filter(a => a.status === 'In Progress').length} in progress`,
    seg('appFilter', ['In Progress', 'Follow up', 'Rejected', 'All']) + `<button class="btn primary" data-act="app-new">+ Add</button>`);
  if (!list.length) return head + '<div class="empty">No applications match.</div>';
  const th = APP_COLS.map(([k, l]) => `<th data-act="sort" data-key="${k}" ${sk === k ? `aria-sort="${dir > 0 ? 'ascending' : 'descending'}"` : ''}>${l}</th>`).join('');
  const rows = list.map(a => `<tr data-act="app-edit" data-id="${esc(a.id)}" style="--wire:${wireVar(appWire(a))}">
    <td class="wire"><span></span></td>
    <td class="co">${esc(a.company)}<div class="sub">${esc(a.industry || '')}</div></td>
    <td class="clip" title="${esc(a.role)}">${esc(a.role)}</td>
    <td data-l="Stage">${esc(a.stage)}</td>
    <td data-l="Status">${esc(a.status)}</td>
    <td data-l="Applied" style="white-space:nowrap">${esc(a.dateApplied)}</td>
    <td data-l="Location" class="clip">${esc(a.location)}</td>
    <td data-l="Contact" class="clip">${esc(a.contact)}${(a.outreach || []).length ? `<div class="sub">${a.outreach.length} contacted${dueOutreach(a).length ? ` · <span style="color:var(--hv);font-weight:700">${dueOutreach(a).length} follow-up due</span>` : ''}</div>` : ''}</td>
    <td data-l="Next" class="clip">${esc(a.nextStep)}</td>
    <td data-l="Notes" class="clip">${esc(a.notes)}</td>
  </tr>`).join('');
  return head + `<div class="tablewrap"><table class="stack"><thead><tr><th style="width:4px;padding:0"></th>${th}</tr></thead><tbody>${rows}</tbody></table></div>`;
}

function viewWaiting() {
  const items = S.data.waiting.items;
  const list = items.filter(w => matchesQ(w.company, w.industry, w.notes, w.appStatus))
    .sort((a, b) => (/^open/i.test(b.appStatus) - /^open/i.test(a.appStatus)) || a.company.localeCompare(b.company));
  const head = toolbar('Waiting for apps', `${items.length} companies`, `<button class="btn primary" data-act="wait-new">+ Add company</button>`);
  if (!list.length) return head + '<div class="empty">No companies match.</div>';
  return head + `<div class="wgrid">${list.map(w => {
    const open = /^open/i.test(w.appStatus || '');
    const url = safeUrl(w.careersUrl);
    const wire = open ? 'can' : /unverified/i.test(w.appStatus || '') ? 'hv' : null;
    return `<div class="wcard" style="--wire:${wireVar(wire)}">
      <h3><span>${esc(w.company)}</span>${open ? '<span class="chip can">Open</span>' : ''}</h3>
      <p>${esc(w.industry || '')}${w.source ? ` · via ${esc(w.source)}` : ''} · checked ${esc(w.lastChecked || 'never')}</p>
      ${w.appStatus ? `<p class="st">${esc(w.appStatus)}</p>` : ''}
      ${w.notes ? `<p>${esc(w.notes)}</p>` : ''}
      ${w.taskAdded ? `<p>To-do: ${esc(w.taskAdded)}</p>` : ''}
      <div class="acts">
        ${url ? `<a class="btn small" href="${esc(url)}" target="_blank" rel="noopener">Careers page</a>` : ''}
        <button class="btn small" data-act="wait-checked" data-id="${esc(w.id)}">Checked today</button>
        <button class="btn small go" data-act="wait-applied" data-id="${esc(w.id)}">Applied</button>
        <button class="btn small" data-act="wait-edit" data-id="${esc(w.id)}">Edit</button>
      </div>
    </div>`;
  }).join('')}</div>`;
}

// Pop-up for the day grid: shows up right away on hover (or tap on a phone) and lists that day's applications with links.
let HEAT_DAYS = new Map();
// Hover a square: a small count shows after a short pause, then the full list of companies if you stay on it.
// Tap (phone) or click: the full list right away, pinned until you tap elsewhere. The pop-up never covers the square.
const HEAT_COUNT_MS = 250, HEAT_LIST_MS = 1100;
let heatTimers = [], heatHide = null, heatPinned = null, heatCell = null, heatFull = false;
function postingUrl(a) {
  if (/^https?:\/\//.test(a.url || '')) return a.url;
  const n = x => String(x || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').trim();
  const words = x => new Set(n(x).split(/\s+/).filter(w => w.length > 2 && !['intern', 'internship', 'summer', '2027', 'the', 'and'].includes(w)));
  const A = words(a.role);
  const job = (S.data.pipeline?.items || []).filter(j => n(j.company) === n(a.company))
    .map(j => ({ j, hit: [...words(j.title)].filter(w => A.has(w)).length }))
    .sort((x, y) => y.hit - x.hit)[0];
  return job && (job.hit > 0 || /not named/i.test(a.role || '')) ? job.j.url : '';
}
function heatPop() {
  let pop = document.getElementById('heatpop');
  if (!pop) {
    pop = document.createElement('div');
    pop.id = 'heatpop'; pop.className = 'heatpop'; pop.setAttribute('role', 'dialog'); pop.hidden = true;
    pop.addEventListener('pointerenter', () => { clearTimeout(heatHide); if (heatCell && !heatFull) showHeat(heatCell, true); });
    pop.addEventListener('pointerleave', () => { if (!heatPinned) heatHide = setTimeout(hideHeat, 200); });
    document.body.appendChild(pop);
  }
  return pop;
}
function clearHeatTimers() { heatTimers.forEach(clearTimeout); heatTimers = []; }
function hideHeat() { clearHeatTimers(); const pop = document.getElementById('heatpop'); if (pop) pop.hidden = true; heatPinned = null; heatCell = null; heatFull = false; }
// Put the pop-up beside the square, never on top of it: above, else below, else to the right or left.
function placeHeat(pop, cell) {
  const r = cell.getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight, gap = 8, vw = window.innerWidth, vh = window.innerHeight;
  const clampX = x => Math.min(Math.max(8, x), vw - pw - 8), clampY = y => Math.min(Math.max(8, y), vh - ph - 8);
  let left, top;
  if (r.top - ph - gap >= 8) { left = clampX(r.left + r.width / 2 - pw / 2); top = r.top - ph - gap; }
  else if (r.bottom + gap + ph <= vh - 8) { left = clampX(r.left + r.width / 2 - pw / 2); top = r.bottom + gap; }
  else if (r.right + gap + pw <= vw - 8) { left = r.right + gap; top = clampY(r.top + r.height / 2 - ph / 2); }
  else if (r.left - gap - pw >= 8) { left = r.left - gap - pw; top = clampY(r.top + r.height / 2 - ph / 2); }
  else { left = clampX(r.left); top = r.bottom + gap; } // tiny screens: below, scrolls inside
  pop.style.left = `${left}px`; pop.style.top = `${top}px`;
  pop.style.maxHeight = `${Math.max(120, top >= r.bottom ? vh - top - 8 : r.top - gap - 8)}px`;
}
function showHeat(cell, full) {
  clearTimeout(heatHide);
  heatCell = cell; heatFull = full;
  const day = cell.dataset.day, list = HEAT_DAYS.get(day) || [];
  const pop = heatPop();
  const date = new Date(`${day}T00:00:00`).toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' });
  const companies = new Set(list.map(a => a.company)).size;
  const head = `<div class="hp-head"><b>${esc(list.length || 'No')} application${list.length === 1 ? '' : 's'}</b>${list.length ? ` · ${esc(companies)} compan${companies === 1 ? 'y' : 'ies'}` : ''}<span class="meta">${esc(date)}</span></div>`;
  pop.classList.toggle('compact', !full || !list.length);
  pop.innerHTML = head + (full && list.length ? `<ul>${list.map(a => {
      const url = postingUrl(a);
      return `<li><div><b>${esc(a.company)}</b><span class="meta">${esc(a.role || '')}</span></div>
        <div class="hp-links"><span class="hp-stage" style="--wire:${wireVar(appWire(a))}">${esc(a.status === 'Rejected' ? 'Rejected' : a.stage || 'Applied')}</span>
        ${url ? `<a href="${esc(safeUrl(url))}" target="_blank" rel="noopener">Posting ↗</a>` : ''}
        <a href="#" data-act="app-edit" data-id="${esc(a.id)}">Details</a></div></li>`;
    }).join('')}</ul>` : (list.length ? '<div class="hp-more meta">Keep hovering to see the companies</div>' : ''));
  pop.hidden = false;
  placeHeat(pop, cell);
}
document.addEventListener('pointerover', e => {
  const c = e.target.closest?.('.hc[data-day]');
  if (!c || heatPinned || e.pointerType === 'touch') return;
  if (c === heatCell) { clearTimeout(heatHide); return; }
  clearHeatTimers();
  if (heatCell) showHeat(c, false); // already showing one: switch right away
  else heatTimers.push(setTimeout(() => showHeat(c, false), HEAT_COUNT_MS));
  heatTimers.push(setTimeout(() => showHeat(c, true), HEAT_LIST_MS));
});
document.addEventListener('pointerout', e => {
  if (!e.target.closest?.('.hc[data-day]') || heatPinned || e.pointerType === 'touch') return;
  if (e.relatedTarget?.closest?.('.hc[data-day]')) return; // moving to another square: pointerover handles it
  clearHeatTimers();
  heatHide = setTimeout(hideHeat, 200);
});
document.addEventListener('click', e => {
  const c = e.target.closest?.('.hc[data-day]');
  if (c) { if (heatPinned === c) hideHeat(); else { clearHeatTimers(); showHeat(c, true); heatPinned = c; } return; }
  if (!e.target.closest?.('#heatpop')) hideHeat();
  else if (e.target.closest('[data-act="app-edit"]')) { e.preventDefault(); hideHeat(); }
});
document.addEventListener('focusin', e => { const c = e.target.closest?.('.hc[data-day]'); if (c) showHeat(c, true); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') hideHeat(); });
window.addEventListener('scroll', () => { if (!heatPinned) hideHeat(); else if (heatCell) placeHeat(heatPop(), heatCell); }, { passive: true });

// GitHub-style grid: one square per day, darker green for more applications that day.
function heatmap(apps) {
  const DAY = 86400000;
  const key = d => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  const byDay = new Map();
  for (const a of apps) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(a.dateApplied || '')) continue;
    if (!byDay.has(a.dateApplied)) byDay.set(a.dateApplied, []);
    byDay.get(a.dateApplied).push(a);
  }
  const today = new Date(); today.setHours(0, 0, 0, 0);
  // Start on the Sunday 26 weeks back, or earlier if your first application is older (up to a year).
  const first = [...byDay.keys()].sort()[0];
  let start = new Date(today.getTime() - 25 * 7 * DAY);
  if (first) { const f = new Date(`${first}T00:00:00`); if (f < start) start = new Date(Math.max(f.getTime(), today.getTime() - 52 * 7 * DAY)); }
  start.setDate(start.getDate() - start.getDay());
  const max = Math.max(1, ...[...byDay.values()].map(v => v.length));
  const level = n => (n === 0 ? 0 : n >= max * 0.75 ? 4 : n >= max * 0.5 ? 3 : n >= max * 0.25 ? 2 : 1);
  const cols = [];
  const months = [];
  let total = 0, best = { n: 0, d: '' };
  for (let w = new Date(start); w <= today; w = new Date(w.getTime() + 7 * DAY)) {
    const cells = [];
    for (let i = 0; i < 7; i++) {
      const d = new Date(w.getTime() + i * DAY);
      if (d > today) { cells.push('<i class="hc out"></i>'); continue; }
      const k = key(d), list = byDay.get(k) || [];
      total += list.length;
      if (list.length > best.n) best = { n: list.length, d: k };
      const label = `${list.length || 'No'} application${list.length === 1 ? '' : 's'} on ${d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}${list.length ? `: ${list.map(a => a.company).join(', ')}` : ''}`;
      cells.push(`<i class="hc l${level(list.length)}" data-day="${k}" tabindex="${list.length ? 0 : -1}" aria-label="${esc(label)}"></i>`);
      if (d.getDate() === 1 || (w.getTime() === start.getTime() && i === 0)) months.push({ col: cols.length, name: d.toLocaleDateString([], { month: 'short' }) });
    }
    cols.push(`<div class="hcol">${cells.join('')}</div>`);
  }
  // Current streak of days in a row with at least one application, ending today or yesterday.
  let streak = 0;
  for (let d = new Date(today); ; d = new Date(d.getTime() - DAY)) {
    if (byDay.has(key(d))) streak++;
    else if (streak === 0 && d.getTime() === today.getTime()) continue;
    else break;
  }
  const monthRow = months.map(m => `<span style="grid-column:${m.col + 1}">${esc(m.name)}</span>`).join('');
  HEAT_DAYS = byDay;
  setTimeout(() => document.querySelectorAll('.heat-scroll').forEach(e => { e.scrollLeft = e.scrollWidth; }), 0);
  return `<div class="panel heat"><h3>Applications per day</h3>
    <div class="heat-scroll"><div class="heat-grid" style="--cols:${cols.length}">
      <div class="hmonths">${monthRow}</div>
      <div class="hdays"><span></span><span>Mon</span><span></span><span>Wed</span><span></span><span>Fri</span><span></span></div>
      <div class="hcols">${cols.join('')}</div>
    </div></div>
    <div class="heat-foot"><span class="meta">${esc(total)} in this period · best day ${best.n ? `${esc(best.n)} (${esc(new Date(`${best.d}T00:00:00`).toLocaleDateString([], { month: 'short', day: 'numeric' }))})` : '-'} · current streak ${esc(streak)} day${streak === 1 ? '' : 's'}</span>
      <span class="hlegend meta">Less <i class="hc l0"></i><i class="hc l1"></i><i class="hc l2"></i><i class="hc l3"></i><i class="hc l4"></i> More</span></div>
  </div>`;
}

function viewSummary() {
  const apps = S.data.applications.items;
  const by = key => apps.reduce((m, a) => ((m[a[key] || 'Unknown'] = (m[a[key] || 'Unknown'] || 0) + 1), m), {});
  const inProg = apps.filter(a => a.status === 'In Progress').length;
  const rejected = apps.filter(a => a.status === 'Rejected').length;
  const interviews = apps.filter(a => /screen|interview|assessment|final|offer/i.test(a.stage) || /interview|screen/i.test(a.notes || '')).length;
  const companies = new Set(apps.map(a => norm(a.company))).size;
  const responded = apps.filter(a => a.status !== 'In Progress' || a.stage !== 'Applied').length;
  const kpi = (n, l, w) => `<div class="kpi" style="--wire:${wireVar(w)}"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`;
  const bars = (obj, wireFn, order) => {
    const entries = (order ? order.filter(k => obj[k]).map(k => [k, obj[k]]) : Object.entries(obj).sort((a, b) => b[1] - a[1]));
    const max = Math.max(1, ...entries.map(e => e[1]));
    return entries.map(([k, v]) => `<div class="barrow" style="--wire:${wireVar(wireFn ? wireFn(k) : null)}"><span class="clip">${esc(k)}</span><div class="track"><div class="fill" style="width:${(v / max) * 100}%"></div></div><span class="num">${v}</span></div>`).join('');
  };
  // Applications per week, last 10 weeks
  const weeks = [];
  const now = new Date(); now.setHours(0, 0, 0, 0);
  const monday = new Date(now); monday.setDate(now.getDate() - ((now.getDay() + 6) % 7));
  for (let i = 9; i >= 0; i--) { const s = new Date(monday); s.setDate(monday.getDate() - 7 * i); weeks.push({ start: s, n: 0 }); }
  for (const a of apps) {
    const d = new Date(`${a.dateApplied}T00:00:00`);
    if (isNaN(d)) continue;
    for (let i = weeks.length - 1; i >= 0; i--) if (d >= weeks[i].start) { if (i < weeks.length) weeks[i].n++; break; }
  }
  const wmax = Math.max(1, ...weeks.map(w => w.n));
  const followups = apps.filter(a => a.nextStep && a.status === 'In Progress');
  const dueList = allDue();
  const pipe = S.data.pipeline.items;
  const stageOrder = (S.data.options.stage || []);
  return `<div class="toolbar"><h2>Summary<small>${esc(apps.length)} applications, ${esc(companies)} companies</small></h2></div>
    <div class="kpis">
      ${kpi(apps.length, 'Applications', 'auto')}
      ${kpi(inProg, 'In progress', 'can')}
      ${kpi(interviews, 'Reached a screen or interview', 'can')}
      ${kpi(rejected, 'Rejected', 'batt')}
      ${kpi(apps.length ? Math.round((responded / apps.length) * 100) + '%' : '-', 'Heard back', 'hv')}
      ${kpi(pipe.filter(j => pipeStatus(j.id) === 'New').length, 'New in pipeline', null)}
    </div>
    ${heatmap(apps)}
    <div class="panels">
      <div class="panel"><h3>Applications per week</h3><div class="weeks">${weeks.map(w => `<div><b>${w.n || ''}</b><span class="b" style="height:${(w.n / wmax) * 100}%"></span>${w.start.getMonth() + 1}/${w.start.getDate()}</div>`).join('')}</div></div>
      <div class="panel"><h3>By stage</h3>${bars(by('stage'), k => STAGE_WIRE[k], stageOrder.length ? stageOrder.concat(Object.keys(by('stage')).filter(k => !stageOrder.includes(k))) : null)}</div>
      <div class="panel"><h3>By industry</h3>${bars(by('industry'), () => 'auto')}</div>
      <div class="panel"><h3>By source</h3>${bars(by('source'), () => 'hv')}</div>
      <div class="panel"><h3>Follow-ups due (${dueList.length + followups.length})</h3>${dueList.length + followups.length ? `<ul class="list">${dueList.map(({ a, o }) => `<li data-act="app-edit" data-id="${esc(a.id)}" style="cursor:pointer"><b>${esc(a.company)}</b>: follow up with ${esc(o.name)} (${esc(o.channel)}, sent ${esc(o.sentOn)})</li>`).join('')}${followups.map(a => `<li data-act="app-edit" data-id="${esc(a.id)}" style="cursor:pointer"><b>${esc(a.company)}</b>: ${esc(a.nextStep)}</li>`).join('')}</ul>` : '<p class="meta">Nothing waiting on you.</p>'}</div>
      <div class="panel"><h3>Outreach</h3>${outreachStats()}</div>
    </div>`;
}

function outreachStats() {
  const all = S.data.applications.items.flatMap(a => a.outreach || []);
  if (!all.length) return '<p class="meta">No outreach logged yet. Open an application and add who you contacted.</p>';
  const c = s => all.filter(o => o.status === s).length;
  const replied = c('Replied') + c('Referred');
  return `<div class="barrow"><span>Contacted</span><div class="track"><div class="fill" style="width:100%"></div></div><span class="num">${all.length}</span></div>
    <div class="barrow" style="--wire:var(--can)"><span>Replied or referred</span><div class="track"><div class="fill" style="width:${(replied / all.length) * 100}%"></div></div><span class="num">${replied}</span></div>
    <div class="barrow" style="--wire:var(--hv)"><span>Waiting</span><div class="track"><div class="fill" style="width:${(c('Sent') / all.length) * 100}%"></div></div><span class="num">${c('Sent')}</span></div>`;
}

/* ---------- dialogs ---------- */
function opts(name) { return S.data.options?.[name] || []; }
function field(name, label, value, { type = 'text', list, select, full, required } = {}) {
  const id = `f-${name}`;
  let input;
  if (select) input = `<select id="${id}" name="${name}">${[...new Set([...(value && !select.includes(value) ? [value] : []), ...select])].map(o => `<option ${o === value ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  else if (type === 'textarea') input = `<textarea id="${id}" name="${name}">${esc(value)}</textarea>`;
  else input = `<input id="${id}" name="${name}" type="${type}" value="${esc(value)}" ${list ? `list="dl-${name}"` : ''} ${required ? 'required' : ''}>${list ? `<datalist id="dl-${name}">${list.map(o => `<option value="${esc(o)}">`).join('')}</datalist>` : ''}`;
  return `<div class="field ${full ? 'full' : ''}"><label for="${id}">${esc(label)}</label>${input}</div>`;
}
function openDialog({ title, body, onSave, onDelete, saveLabel = 'Save', wide = false, noSave = false }) {
  const dlg = $('#dlg');
  dlg.classList.toggle('wide', wide);
  $('#dlgform').innerHTML = `<div class="dhead"><h3>${esc(title)}</h3><button class="iconbtn" value="cancel" formnovalidate aria-label="Close">✕</button></div>
    <div class="dbody">${body}</div>
    <div class="dfoot">${onDelete ? '<button type="button" class="btn danger left" id="dlgdel">Delete</button>' : ''}<button class="btn" value="cancel" formnovalidate>${noSave ? 'Close' : 'Cancel'}</button>${noSave ? '' : `<button class="btn primary" value="save" id="dlgsave">${esc(saveLabel)}</button>`}</div>`;
  dlg.onclose = null;
  $('#dlgform').onsubmit = async e => {
    if (e.submitter?.value !== 'save') return;
    e.preventDefault();
    const fd = Object.fromEntries(new FormData($('#dlgform')).entries());
    fd._checks = [...$('#dlgform').querySelectorAll('input[type=checkbox]')].reduce((m, c) => ((m[c.name] = c.checked), m), {});
    const btn = $('#dlgsave'); btn.disabled = true; btn.textContent = 'Saving...';
    try { await onSave(fd); dlg.close(); } catch (err) { toast(err.message, true); btn.disabled = false; btn.textContent = saveLabel; }
  };
  if (onDelete) $('#dlgdel').onclick = async () => {
    if (!confirm('Delete this entry? It stays in the repo history if you ever need it back.')) return;
    try { await onDelete(); dlg.close(); } catch (err) { toast(err.message, true); }
  };
  dlg.showModal();
  if (!noSave) dlg.querySelector('input, select, textarea')?.focus();
}

function appForm(a, extra = '') {
  return field('company', 'Company', a.company, { required: true }) + field('role', 'Role', a.role, { required: true })
    + field('stage', 'Stage', a.stage || 'Applied', { select: opts('stage') }) + field('status', 'Status', a.status || 'In Progress', { select: opts('status') })
    + field('dateApplied', 'Date applied', a.dateApplied || today(), { type: 'date' }) + field('industry', 'Industry', a.industry, { list: opts('industry') })
    + field('source', 'Source', a.source, { list: opts('source') }) + field('portal', 'Portal', a.portal, { list: opts('portal') })
    + field('location', 'Location', a.location, { full: true }) + field('contact', 'Contact / referral', a.contact, { full: true })
    + field('nextStep', 'Next step', a.nextStep, { full: true }) + field('notes', 'Notes', a.notes, { type: 'textarea', full: true })
    + field('url', 'Posting link', a.url, { full: true, type: 'url' }) + extra;
}
const APP_KEYS = ['company', 'role', 'stage', 'status', 'dateApplied', 'industry', 'source', 'portal', 'location', 'contact', 'nextStep', 'notes', 'url'];
const pickApp = fd => Object.fromEntries(APP_KEYS.map(k => [k, (fd[k] || '').trim()]));

/* ---------- outreach log ---------- */
const OUT_CHANNELS = ['Email', 'LinkedIn', 'In person', 'Referral ask', 'Other'];
const OUT_STATUS = ['Sent', 'Replied', 'Referred', 'No reply', 'Not sent yet'];
const addDays = (iso, n) => { const d = new Date(`${iso}T12:00:00`); if (isNaN(d)) return ''; d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); };
const dueOutreach = a => (a.outreach || []).filter(o => o.status === 'Sent' && o.followUpOn && o.followUpOn <= today());
function allDue() {
  return S.data.applications.items.filter(a => a.status === 'In Progress').flatMap(a => dueOutreach(a).map(o => ({ a, o })));
}
function outreachRow(o, key) {
  const n = k => `o_${key}_${k}`;
  const sel = (name, list, v) => `<select name="${name}" aria-label="${name}">${list.map(x => `<option ${x === v ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select>`;
  return `<div class="orow">
    <input name="${n('name')}" value="${esc(o.name || '')}" placeholder="${key === 'new' ? 'Add a person (name, role)' : 'Name'}" aria-label="Contact name">
    ${sel(n('channel'), OUT_CHANNELS, o.channel || 'Email')}
    <input name="${n('handle')}" value="${esc(o.handle || '')}" placeholder="Email or profile link" aria-label="Email or profile">
    <label class="mini">Sent<input type="date" name="${n('sentOn')}" value="${esc(o.sentOn || (key === 'new' ? today() : ''))}"></label>
    <label class="mini">Follow up<input type="date" name="${n('followUpOn')}" value="${esc(o.followUpOn || '')}"></label>
    ${sel(n('status'), OUT_STATUS, o.status || 'Sent')}
  </div>`;
}
function outreachSection(a) {
  const list = a.outreach || [];
  return `<div class="field full"><label>Outreach (${list.length})</label>
    <p class="meta" style="margin:0 0 6px">People you've contacted about this role. Clear a name to remove that row. Follow-up defaults to a week after sending.</p>
    ${list.map((o, i) => outreachRow(o, i)).join('')}${outreachRow({}, 'new')}</div>`;
}
function pickOutreach(fd, prev = []) {
  const read = key => ({
    name: (fd[`o_${key}_name`] || '').trim(), channel: fd[`o_${key}_channel`], handle: (fd[`o_${key}_handle`] || '').trim(),
    sentOn: fd[`o_${key}_sentOn`] || '', followUpOn: fd[`o_${key}_followUpOn`] || '', status: fd[`o_${key}_status`],
  });
  const out = [];
  prev.forEach((o, i) => { const r = read(i); if (r.name) out.push({ ...o, ...r }); });
  const fresh = read('new');
  if (fresh.name) out.push({ id: uid('o'), ...fresh, followUpOn: fresh.followUpOn || (fresh.status === 'Sent' && fresh.sentOn ? addDays(fresh.sentOn, 7) : '') });
  return out;
}

async function addApplication(app, why) {
  const item = { id: uid('a'), ...app };
  const next = await updateFile(FILES.applications, d => ({ ...d, items: [...(d.items || []), item] }), `Tracker: ${why} ${app.company}`);
  S.data.applications = next;
  return item;
}
async function setPipeStatus(id, status) {
  const next = await updateFile(FILES.status, d => {
    d.items ||= {};
    if (status === 'New') delete d.items[id]; else d.items[id] = { status, at: new Date().toISOString() };
    return d;
  }, `Tracker: ${status.toLowerCase()} pipeline match`);
  S.data.status = next;
}

/* ---------- packets ---------- */
function copyBlock(id, label, text, rows = 8) {
  return `<div class="field full"><label for="${id}">${esc(label)}</label><textarea id="${id}" rows="${rows}" readonly>${esc(text)}</textarea>
    <div class="row"><button type="button" class="btn small" data-act="copy" data-from="${id}">Copy</button></div></div>`;
}
function gmailLink(subject, body, to = '') {
  return `https://mail.google.com/mail/?view=cm&fs=1${to ? `&to=${encodeURIComponent(to)}` : ''}&su=${encodeURIComponent(subject || '')}&body=${encodeURIComponent(body || '')}`;
}
function packetBody(pk, job) {
  const parts = [];
  if (pk.status === 'needs-key' || pk.status === 'error') {
    parts.push(`<div class="field full notice ${pk.status === 'error' ? 'bad' : ''}">${esc(pk.status === 'error' ? `Build failed: ${pk.error}` : 'Waiting on drafting. Add the ANTHROPIC_API_KEY secret to draft automatically, or tell Claude in chat "draft my waiting packets". The job description and questions are already saved below.')}</div>`);
  }
  if (pk.fit?.summary) parts.push(`<div class="field full"><label>Fit</label><p class="pk">${esc(pk.fit.summary)}</p>${pk.fit.gaps?.length ? `<p class="pk meta">Not shown on your resume: ${esc(pk.fit.gaps.join('; '))}</p>` : ''}</div>`);
  const flagged = pk.check?.unsupported || [];
  if (flagged.length) parts.push(`<div class="field full notice bad"><b>Check these before sending</b> (claims your resume doesn't back up):<ul>${flagged.map(f => `<li>"${esc(f.text)}" <span class="meta">${esc(f.why || '')}</span></li>`).join('')}</ul></div>`);
  else if (pk.check && !pk.check.error) parts.push(`<div class="field full notice ok">Claim check passed: everything about you traces back to your resume.</div>`);
  if (pk.check?.fixed?.length) parts.push(`<div class="field full"><details><summary class="meta">Fixed automatically before saving (${pk.check.fixed.length})</summary><ul class="pk">${pk.check.fixed.map(f => `<li>"${esc(f.text)}" <span class="meta">${esc(f.why || '')}</span></li>`).join('')}</ul></details></div>`);
  const voiceLeft = Object.entries(pk.voice?.remaining || {});
  if (voiceLeft.length) parts.push(`<div class="field full notice bad"><b>Still sounds AI-written in places</b>:<ul>${voiceLeft.map(([k, hits]) => `<li>${esc(k)}: ${hits.map(h => `"${esc(h.phrase)}" (${esc(h.why)})`).join(', ')}</li>`).join('')}</ul></div>`);
  const rw = Object.entries(pk.resume?.text || {});
  if (rw.length || pk.resumeNotes?.length) {
    const orig = new Map();
    const r = S.data.resume;
    if (r) { for (const e of r.experience) for (const ro of e.roles) for (const b of ro.bullets) orig.set(b.id, b.text); for (const pj of r.projects) for (const b of pj.bullets) orig.set(b.id, b.text); }
    parts.push(`<div class="field full"><label>Reworded for this posting (${rw.length})</label><details><summary class="meta">Compare with your original bullets</summary><ul class="pk">${rw.map(([id, t]) => `<li><b>${esc(t)}</b><br><span class="meta">was: ${esc(orig.get(id) || id)}</span></li>`).join('')}</ul>${pk.resumeNotes?.length ? `<p class="pk meta">Kept original wording for: ${pk.resumeNotes.map(n => esc(`${n.id} (${n.why})`)).join('; ')}</p>` : ''}</details></div>`);
  }
  if (pk.resume) parts.push(`<div class="field full"><label>Tailored resume</label><div class="row"><button type="button" class="btn small primary" data-act="packet-resume" data-id="${esc(pk.id)}">Open printable resume</button><span class="meta">Opens a print-ready page. Choose "Save as PDF".</span></div></div>`);
  parts.push(`<div class="field full"><label for="pk-cmd">Fill the application on your laptop</label>
    <input id="pk-cmd" readonly value="${esc(`npm run apply -- "${pk.id}"`)}">
    <div class="row"><button type="button" class="btn small" data-act="copy" data-from="pk-cmd">Copy</button><span class="meta">Run in your internship-pipeline folder. It fills the form and stops before Submit.</span></div></div>`);
  if (pk.coverLetter) parts.push(copyBlock('pk-cover', 'Cover letter', pk.coverLetter, 12) + `<div class="field full" style="margin-top:-6px"><div class="row"><button type="button" class="btn small" data-act="packet-cover-print" data-id="${esc(pk.id)}">Printable cover letter</button></div></div>`);
  (pk.answers || []).forEach((q, i) => parts.push(copyBlock(`pk-a${i}`, q.question, q.answer, 5)));
  const o = pk.outreach;
  if (o) {
    const company = encodeURIComponent(pk.company);
    parts.push(`<div class="field full"><label>Who to reach out to</label><p class="pk">${esc((o.lookFor || []).join(', ') || 'Engineers on the team, a university recruiter')}</p>
      <div class="row"><a class="btn small" target="_blank" rel="noopener" href="https://www.linkedin.com/search/results/people/?keywords=${company}%20engineer">Find engineers</a>
      <a class="btn small" target="_blank" rel="noopener" href="https://www.linkedin.com/search/results/people/?keywords=${company}%20university%20recruiter">Find recruiters</a>
      <a class="btn small" target="_blank" rel="noopener" href="https://www.linkedin.com/search/results/people/?keywords=${company}%20%22University%20of%20Texas%22">UT alumni there</a></div></div>`);
    // People found for this job, each with their own email and LinkedIn note.
    if (pk.contacts?.length) {
      parts.push(`<div class="field full"><label>People to contact (${pk.contacts.length})</label><p class="pk meta">${esc(pk.contactsNote || '')} Check each profile before reaching out.</p></div>`);
      pk.contacts.forEach((c, i) => {
        parts.push(`<div class="field full"><label>${esc(c.name)} · ${esc(c.title)} <span class="meta">(${esc(c.kind)})</span></label>
          <p class="pk meta">${esc(c.why || '')}${c.evidence ? ` · "${esc(c.evidence)}"` : ''}</p>
          <div class="row"><a class="btn small" target="_blank" rel="noopener" href="${esc(safeUrl(c.profileUrl))}">Open profile</a>
          ${c.email ? `<span class="meta">${esc(c.email)} (unverified guess)</span>` : '<span class="meta">No email found; message on LinkedIn or find it on the company site.</span>'}</div></div>`);
        if (c.emailBody) parts.push(copyBlock(`pk-c${i}-email`, `Email to ${c.name} · subject: ${c.emailSubject || ''}`, c.emailBody, 7) + `<div class="field full" style="margin-top:-6px"><div class="row"><a class="btn small" target="_blank" rel="noopener" href="${esc(gmailLink(c.emailSubject, c.emailBody, c.email || ''))}">Open as a Gmail draft</a></div></div>`);
        if (c.linkedinNote) parts.push(copyBlock(`pk-c${i}-li`, `LinkedIn note to ${c.name} (${c.linkedinNote.length}/300)`, c.linkedinNote, 3));
      });
    } else if (pk.contactsNote) parts.push(`<div class="field full"><p class="pk meta">${esc(pk.contactsNote)}</p></div>`);
    if (o.emailBody) parts.push(copyBlock('pk-email', `Email to an engineer · subject: ${o.emailSubject || ''}`, o.emailBody, 8) + `<div class="field full" style="margin-top:-6px"><div class="row"><a class="btn small" target="_blank" rel="noopener" href="${esc(gmailLink(o.emailSubject, o.emailBody))}">Open as a Gmail draft</a><span class="meta">Replace [Name] and add the address before sending.</span></div></div>`);
    if (o.recruiterEmailBody) parts.push(copyBlock('pk-remail', 'Email to a recruiter', o.recruiterEmailBody, 6) + `<div class="field full" style="margin-top:-6px"><div class="row"><a class="btn small" target="_blank" rel="noopener" href="${esc(gmailLink(o.emailSubject, o.recruiterEmailBody))}">Open as a Gmail draft</a></div></div>`);
    if (o.linkedinNote) parts.push(copyBlock('pk-li', `LinkedIn connection note (${o.linkedinNote.length}/300)`, o.linkedinNote, 3));
  }
  if (pk.questions?.length && !pk.answers?.length) parts.push(`<div class="field full"><label>Questions on the application</label><ul class="pk">${pk.questions.map(q => `<li>${esc(q.label)}</li>`).join('')}</ul></div>`);
  parts.push(`<div class="field full"><label>Job description (${esc(pk.jdSource || 'unknown')})</label>${pk.jd ? `<details><summary class="meta">Show ${esc(pk.jd.length.toLocaleString())} characters</summary><p class="pk jd">${esc(pk.jd)}</p></details>` : '<p class="pk meta">Couldn\'t read the posting automatically. Paste it below and rebuild for a much better packet.</p>'}
    <div class="row"><button type="button" class="btn small" data-act="packet-paste" data-id="${esc(pk.id)}">Paste job description</button><button type="button" class="btn small" data-act="packet-rebuild" data-id="${esc(pk.id)}">Rebuild packet</button>
    <span class="meta">Built ${esc(new Date(pk.builtAt).toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }))}${pk.cost ? `, about $${esc(pk.cost)}` : ''}</span></div></div>`);
  return parts.join('');
}

function resumeHtml(pk) {
  const r = S.data.resume;
  if (!r) return '<p>Resume data (config/resume.json) is missing.</p>';
  const sel = pk.resume;
  const bulletText = new Map();
  for (const e of r.experience) for (const ro of e.roles) for (const b of ro.bullets) bulletText.set(b.id, b.text);
  for (const pj of r.projects) for (const b of pj.bullets) bulletText.set(b.id, b.text);
  for (const [id, t] of Object.entries(sel.text || {})) if (bulletText.has(id)) bulletText.set(id, t); // reworded for this posting
  const li = ids => `<ul>${ids.map(id => bulletText.get(id)).filter(Boolean).map(t => `<li>${esc(t)}</li>`).join('')}</ul>`;
  const row = (l, rgt, cls = '') => `<div class="r ${cls}"><span>${l}</span><span>${esc(rgt || '')}</span></div>`;
  const include = new Set(sel.includeRoles || []);
  const exp = r.experience.map(e => {
    const roles = e.roles.filter(ro => include.has(ro.id));
    if (!roles.length) return '';
    return row(`<b>${esc(e.org)}</b>`, e.date) + roles.map(ro => row(`<i>${esc(ro.title)}</i>`, ro.date, 'sub') + li(sel.roles[ro.id] || ro.bullets.map(b => b.id))).join('');
  }).join('');
  const proj = sel.projects.map(sp => {
    const pj = r.projects.find(x => x.id === sp.id);
    if (!pj) return '';
    return row(`<b>${esc(pj.title)}</b>${pj.link ? ` | <a href="${esc(safeUrl(pj.link))}">link</a>` : ''}`, pj.date) + li(sp.bullets);
  }).join('');
  const skills = sel.skillsOrder.map(id => r.skills.find(s => s.id === id)).filter(Boolean)
    .map(s => ({ label: s.label, items: sel.skills?.[s.id] || s.items })).filter(s => s.items.length)
    .map(s => `<li><b>${esc(s.label)}:</b> ${esc(s.items.join(', '))}</li>`).join('');
  const ed = r.education.map(e => row(`<b>${esc(e.school)}</b>`, '') + row(`${esc(e.degree)}`, e.date, 'sub') + `<div class="cw">Coursework: ${esc(e.coursework)}</div>`).join('');
  const contact = r.contact.map(c => (c.url ? `<a href="${esc(c.url)}">${esc(c.text)}</a>` : esc(c.text))).join(' · ');
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(r.name)} Resume - ${esc(pk.company)}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Caladea:ital,wght@0,400;0,700;1,400&display=swap">
<style>
@page { size: letter; margin: 0.45in 0.5in; }
* { box-sizing: border-box; }
body { font-family: Caladea, "Cambria", Georgia, serif; font-size: 10.6pt; line-height: 1.22; color: #000; margin: 0; }
.page { max-width: 7.5in; margin: 0 auto; padding: 0.3in 0 0; }
h1 { text-align: center; font-size: 22pt; margin: 0 0 2pt; font-weight: 700; }
.contact { text-align: center; font-size: 10pt; margin-bottom: 6pt; }
a { color: inherit; text-decoration: none; }
h2 { font-size: 12pt; font-weight: 700; margin: 8pt 0 3pt; padding-bottom: 1pt; border-bottom: 0.8pt solid #000; font-variant: small-caps; letter-spacing: .02em; }
.r { display: flex; justify-content: space-between; gap: 12pt; padding-left: 6pt; }
.r span:last-child { white-space: nowrap; }
.r.sub { margin-top: 1pt; }
.cw { padding-left: 6pt; }
ul { margin: 1pt 0 3pt; padding-left: 20pt; }
li { margin: 0.6pt 0; }
.bar { position: sticky; top: 0; background: #122230; color: #fff; padding: 8px 12px; font: 14px Arial, sans-serif; display: flex; gap: 10px; align-items: center; }
.bar button { font: inherit; padding: 4px 10px; cursor: pointer; }
@media print { .bar { display: none; } .page { padding: 0; } }
</style></head><body>
<div class="bar">Tailored for ${esc(pk.company)}: ${esc(pk.title)} <button onclick="print()">Print / Save as PDF</button></div>
<div class="page">
<h1>${esc(r.name)}</h1><div class="contact">${contact}</div>
<h2>Education</h2>${ed}
<h2>Experience</h2>${exp}
<h2>Projects</h2>${proj}
<h2>Technical Skills</h2><ul>${skills}</ul>
</div>
<script>
// Shrink the font a little if the tailored resume runs past one letter page.
(function () {
  var pg = document.querySelector('.page'), max = (11 - 0.9) * 96, fs = 10.6;
  function h() { return pg.scrollHeight - parseFloat(getComputedStyle(pg).paddingTop); }
  (document.fonts ? document.fonts.ready : Promise.resolve()).then(function () {
    while (h() > max && fs > 9.6) { fs = Math.round((fs - 0.2) * 10) / 10; document.body.style.fontSize = fs + 'pt'; }
    if (h() > max) document.querySelector('.bar').insertAdjacentHTML('beforeend', ' <b style="color:#ffb37a">Runs past one page: rebuild or drop a bullet.</b>');
  });
})();
</script></body></html>`;
}
function coverHtml(pk) {
  const r = S.data.resume || { name: 'Leo Block', contact: [] };
  const paras = String(pk.coverLetter || '').split(/\n\s*\n/).map(t => `<p>${esc(t).replace(/\n/g, '<br>')}</p>`).join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(r.name)} Cover Letter - ${esc(pk.company)}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Caladea:wght@400;700&display=swap">
<style>@page { size: letter; margin: 0.9in; } body { font-family: Caladea, Georgia, serif; font-size: 11.5pt; line-height: 1.4; max-width: 6.7in; margin: 0 auto; padding: .4in 0; }
h1 { font-size: 18pt; margin: 0; } .c { margin-bottom: 18pt; font-size: 10.5pt; } a { color: inherit; text-decoration: none; }
.bar { position: sticky; top: 0; background: #122230; color: #fff; padding: 8px 12px; font: 14px Arial, sans-serif; } .bar button { font: inherit; padding: 4px 10px; }
@media print { .bar { display: none; } body { padding: 0; } }</style></head><body>
<div class="bar"><button onclick="print()">Print / Save as PDF</button></div>
<h1>${esc(r.name)}</h1><div class="c">${r.contact.map(c => esc(c.text)).join(' · ')}</div>
<p>${esc(new Date().toLocaleDateString([], { month: 'long', day: 'numeric', year: 'numeric' }))}</p><p>${esc(pk.company)} hiring team</p>${paras}</body></html>`;
}
function openPrintable(html) {
  const w = window.open('', '_blank');
  if (!w) { toast('Allow pop-ups for this site to open the printable page.', true); return; }
  w.document.open(); w.document.write(html); w.document.close();
}
async function requestRebuild(id, extra = {}) {
  S.data.packetReq = await updateFile(FILES.packetReq, d => { d.items ||= {}; d.items[id] = { at: new Date().toISOString(), ...extra }; return d; }, 'Tracker: rebuild packet');
  delete S.packetCache?.[packetName(id)];
  toast('Rebuilding. It takes about a minute; reopen the packet after.');
  await sleep(2500); await loadRuns(); render(); watchRuns();
}

/* ---------- actions ---------- */
const ACTIONS = {
  async 'toggle-pause'() {
    const paused = !S.data.control.paused;
    S.data.control = await updateFile(FILES.control, d => ({ ...d, paused }), paused ? 'Tracker: pause daily scan' : 'Tracker: resume daily scan');
    render();
    toast(paused ? 'Paused. Scheduled scans will skip until you resume.' : 'Resumed. The next scan runs on schedule.');
  },
  async 'run-scan'() {
    await dispatch(CFG.scanWorkflow, { force: 'true', include_seen: 'false' });
    toast('Scan started. It takes about a minute; this page updates when it finishes.');
    await sleep(2500); await loadRuns(); render(); watchRuns();
  },
  async 'run-detect'() {
    await dispatch(CFG.detectWorkflow, { all: 'false' });
    toast('Board detection started.');
    await sleep(2500); await loadRuns(); render(); watchRuns();
  },
  async refresh() { await loadAll(); toast('Up to date.'); },
  async seg(el) { S.prefs[el.dataset.key] = el.dataset.val; savePrefs(); render(); },
  async sort(el) {
    const k = el.dataset.key;
    const [sk, dir] = S.prefs.appSort;
    S.prefs.appSort = [k, sk === k ? -dir : (k === 'dateApplied' ? -1 : 1)];
    savePrefs(); render();
  },
  async 'pipe-approve'(el) {
    const id = el.dataset.id;
    await setPipeStatus(id, 'Approved');
    await listPackets();
    render();
    if (S.packets?.has(packetName(id))) { toast('Approved. Opening its packet.'); await ACTIONS['packet-open']({ dataset: { id } }); }
    else toast('Approved. Its packet is being built; find it under the Approved filter in about a minute.');
    watchRuns();
  },
  async 'pipe-skip'(el) { await setPipeStatus(el.dataset.id, 'Skipped'); render(); toast('Skipped.'); },
  async 'pipe-undo'(el) { await setPipeStatus(el.dataset.id, 'New'); render(); },
  async 'pipe-applied'(el) {
    const j = S.data.pipeline.items.find(x => x.id === el.dataset.id);
    if (!j) return;
    openDialog({
      title: 'Log application',
      saveLabel: 'Add to Applications',
      body: appForm({ company: j.company, role: j.title, source: 'Pipeline', portal: guessPortal(j.url), location: (j.locations || []).join('; '), url: j.url, notes: (j.terms || []).join(', ') }),
      onSave: async fd => {
        await addApplication(pickApp(fd), 'applied to');
        await setPipeStatus(j.id, 'Applied');
        render(); toast(`Added ${fd.company} to Applications.`);
      },
    });
  },
  async 'app-new'() {
    openDialog({ title: 'Add application', body: appForm({}, outreachSection({})), onSave: async fd => { await addApplication({ ...pickApp(fd), outreach: pickOutreach(fd) }, 'add'); render(); toast('Added.'); } });
  },
  async 'app-edit'(el) {
    const a = S.data.applications.items.find(x => x.id === el.dataset.id);
    if (!a) return;
    openDialog({
      title: `${a.company}`,
      body: appForm(a, outreachSection(a)),
      wide: true,
      onSave: async fd => {
        const outreach = pickOutreach(fd, a.outreach || []);
        S.data.applications = await updateFile(FILES.applications, d => ({ ...d, items: d.items.map(x => (x.id === a.id ? { ...x, ...pickApp(fd), outreach } : x)) }), `Tracker: update ${a.company}`);
        render(); toast('Saved.');
      },
      onDelete: async () => {
        S.data.applications = await updateFile(FILES.applications, d => ({ ...d, items: d.items.filter(x => x.id !== a.id) }), `Tracker: remove ${a.company} application`);
        render(); toast('Deleted.');
      },
    });
  },
  async 'wait-new'() { waitDialog({}); },
  async 'wait-edit'(el) { waitDialog(S.data.waiting.items.find(x => x.id === el.dataset.id) || {}); },
  async 'wait-checked'(el) {
    S.data.waiting = await updateFile(FILES.waiting, d => ({ ...d, items: d.items.map(x => (x.id === el.dataset.id ? { ...x, lastChecked: today() } : x)) }), 'Tracker: checked company');
    render(); toast('Marked checked today.');
  },
  async 'wait-applied'(el) {
    const w = S.data.waiting.items.find(x => x.id === el.dataset.id);
    if (!w) return;
    openDialog({
      title: `Applied to ${w.company}`,
      saveLabel: 'Add to Applications',
      body: appForm({ company: w.company, industry: (w.industry || '').replace(/\s*\(.*\)$/, ''), source: w.source, url: w.careersUrl }, `<label class="check"><input type="checkbox" name="removeWaiting" checked> Remove ${esc(w.company)} from Waiting (uncheck if you're still waiting on other roles there)</label>`),
      onSave: async fd => {
        await addApplication(pickApp(fd), 'applied to');
        if (fd._checks.removeWaiting) S.data.waiting = await updateFile(FILES.waiting, d => ({ ...d, items: d.items.filter(x => x.id !== w.id) }), `Tracker: ${w.company} moved to Applications`);
        render(); toast(`Added ${fd.company} to Applications.`);
      },
    });
  },
  async 'open-repo'() { window.open(`https://github.com/${CFG.owner}/${CFG.repo}`, '_blank', 'noopener'); },
  async 'open-actions'() { window.open(`https://github.com/${CFG.owner}/${CFG.repo}/actions`, '_blank', 'noopener'); },
  async pair() {
    const blob = store.get(ENC_KEY);
    if (!blob) { toast('Set a password first.', true); return; }
    const link = `${location.origin}${location.pathname}#pair=${blob}`;
    openDialog({
      title: 'Set up my phone',
      saveLabel: 'Done',
      body: `<div class="field full"><p class="meta" style="margin:0">Scan this with your phone's camera, then enter your password on the phone. The link carries your token encrypted with your password, so it's useless without the password. Don't post it anywhere anyway.</p></div>
        <div class="field full" style="align-items:center"><div id="qr" style="background:#fff;padding:12px;border-radius:6px;line-height:0"></div></div>
        <div class="field full"><label for="pairlink">Or send yourself this link</label><input id="pairlink" readonly value="${esc(link)}"></div>
        <div class="field full"><button type="button" class="btn" data-act="copy-pair">Copy link</button></div>`,
      onSave: async () => {},
    });
    try {
      await loadScript('https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js');
      new window.QRCode($('#qr'), { text: link, width: 220, height: 220, correctLevel: window.QRCode.CorrectLevel.L });
    } catch { $('#qr').outerHTML = '<p class="meta">QR code could not load. Copy the link instead.</p>'; }
  },
  async 'copy-pair'() {
    const i = $('#pairlink'); i.select();
    try { await navigator.clipboard.writeText(i.value); toast('Link copied.'); } catch { document.execCommand('copy'); toast('Link copied.'); }
  },
  async 'change-password'() {
    openDialog({
      title: 'Change password',
      body: field('pwnew', 'New password (8+ characters)', '', { type: 'password', full: true, required: true }) + field('pwnew2', 'Same password again', '', { type: 'password', full: true, required: true })
        + '<p class="meta" style="grid-column:1/-1;margin:0">This changes the password on this device. Set up your phone again afterwards to change it there too.</p>',
      onSave: async fd => {
        if ((fd.pwnew || '').length < 8) throw new Error('Use at least 8 characters.');
        if (fd.pwnew !== fd.pwnew2) throw new Error("Those passwords don't match.");
        store.set(ENC_KEY, await sealToken(S.token, fd.pwnew));
        toast('Password changed on this device.');
      },
    });
  },
  async forget() {
    if (!confirm('Remove the saved token from this device? You will need to paste a token again.')) return;
    store.set(ENC_KEY, ''); showLock('setup');
  },
  async 'packet-open'(el) {
    const id = el.dataset.id;
    const job = S.data.pipeline.items.find(x => x.id === id) || {};
    const pk = await getPacket(id);
    if (!pk) { toast('No packet yet.', true); return; }
    openDialog({ title: `${pk.company}: ${pk.title}`, body: packetBody(pk, job), wide: true, noSave: true, onSave: async () => {} });
  },
  async copy(el) {
    const t = document.getElementById(el.dataset.from);
    if (!t) return;
    try { await navigator.clipboard.writeText(t.value); } catch { t.select(); document.execCommand('copy'); }
    el.textContent = 'Copied'; setTimeout(() => { if (el.isConnected) el.textContent = 'Copy'; }, 1500);
  },
  async 'packet-resume'(el) { const pk = await getPacket(el.dataset.id); if (pk) openPrintable(resumeHtml(pk)); },
  async 'packet-cover-print'(el) { const pk = await getPacket(el.dataset.id); if (pk) openPrintable(coverHtml(pk)); },
  async 'packet-rebuild'(el) { $('#dlg').close(); await requestRebuild(el.dataset.id); },
  async 'packet-paste'(el) {
    const id = el.dataset.id;
    $('#dlg').close();
    openDialog({
      title: 'Paste the job description',
      saveLabel: 'Rebuild packet',
      body: field('jd', 'Job description', '', { type: 'textarea', full: true, required: true })
        + field('questions', 'Application questions (optional, one per line)', '', { type: 'textarea', full: true }),
      onSave: async fd => {
        const questions = String(fd.questions || '').split('\n').map(s => s.trim()).filter(Boolean);
        await requestRebuild(id, { jd: String(fd.jd || '').slice(0, 20000), ...(questions.length ? { questions } : {}) });
      },
    });
  },
  async export() {
    const blob = new Blob([JSON.stringify(S.data, null, 1)], { type: 'application/json' });
    const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `internship-tracker-${today()}.json` });
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  },
};

function waitDialog(w) {
  const isNew = !w.id;
  openDialog({
    title: isNew ? 'Add company to watch' : w.company,
    body: field('company', 'Company', w.company, { required: true }) + field('industry', 'Industry', w.industry, { list: opts('industry') })
      + field('careersUrl', 'Careers page', w.careersUrl, { full: true, type: 'url' }) + field('source', 'Source', w.source, { list: opts('source') })
      + field('lastChecked', 'Last checked', w.lastChecked || today(), { type: 'date' })
      + field('appStatus', 'Application status', w.appStatus, { full: true }) + field('notes', 'Notes', w.notes, { type: 'textarea', full: true })
      + field('taskAdded', 'To-do added', w.taskAdded, { full: true })
      + (isNew ? '<p class="meta" style="grid-column:1/-1;margin:0">The weekly board check will look for this company\'s Greenhouse, Lever, or Ashby page and start pulling its openings.</p>' : ''),
    onSave: async fd => {
      const v = Object.fromEntries(['company', 'industry', 'careersUrl', 'source', 'lastChecked', 'appStatus', 'notes', 'taskAdded'].map(k => [k, (fd[k] || '').trim()]));
      S.data.waiting = await updateFile(FILES.waiting, d => ({
        ...d,
        items: isNew ? [...(d.items || []), { id: uid('w'), ...v }] : d.items.map(x => (x.id === w.id ? { ...x, ...v } : x)),
      }), `Tracker: ${isNew ? 'watch' : 'update'} ${v.company}`);
      render(); toast('Saved.');
    },
    onDelete: isNew ? null : async () => {
      S.data.waiting = await updateFile(FILES.waiting, d => ({ ...d, items: d.items.filter(x => x.id !== w.id) }), `Tracker: stop watching ${w.company}`);
      render(); toast('Removed.');
    },
  });
}

/* ---------- run watching ---------- */
function watchRuns() {
  clearTimeout(S.polling);
  if (DEMO || !S.runs.some(r => r.status !== 'completed')) return;
  S.polling = setTimeout(async () => {
    const before = S.runs.filter(r => r.status !== 'completed').map(r => r.id);
    await loadRuns();
    const finished = S.runs.filter(r => before.includes(r.id) && r.status === 'completed');
    if (finished.length) {
      const f = finished[0];
      const r = await readFile(FILES.pipeline); S.data.pipeline = r.data || S.data.pipeline;
      const lr = await readFile(FILES.lastRun); S.data.lastRun = lr.data;
      await listPackets();
      toast(f.conclusion === 'success' ? `${f.name} finished.` : `${f.name} ${f.conclusion}. Check Run history.`, f.conclusion !== 'success');
    }
    render();
    watchRuns();
  }, 8000);
}

/* ---------- misc UI ---------- */
let toastTimer;
function toast(msg, bad = false) {
  const t = $('#toast');
  t.textContent = msg; t.className = bad ? 'bad' : ''; t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), bad ? 6000 : 3000);
}
function setFoot(s) { $('#footstatus').textContent = s + (DEMO ? ' · demo data' : ''); }
function applyTheme() {
  if (S.prefs.theme) document.documentElement.dataset.theme = S.prefs.theme;
  else delete document.documentElement.dataset.theme;
}

document.addEventListener('click', async e => {
  const tab = e.target.closest('#tabs button');
  if (tab) { S.view = tab.dataset.view; S.q = ''; history.replaceState(null, '', `#${S.view}`); render(); return; }
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const fn = ACTIONS[el.dataset.act];
  if (!fn) return;
  if (el.tagName === 'A') e.preventDefault();
  if (el.tagName === 'BUTTON') el.disabled = true;
  try { await fn(el); } catch (err) { if (err.message !== 'Unauthorized') toast(err.message, true); } finally { if (el.isConnected && el.tagName === 'BUTTON') el.disabled = false; }
});
document.addEventListener('input', e => {
  if (e.target.id !== 'search') return;
  S.q = e.target.value;
  const pos = e.target.selectionStart;
  render();
  const s = $('#search'); if (s) { s.focus(); try { s.setSelectionRange(pos, pos); } catch { /* ignore */ } }
});
$('#theme').addEventListener('click', () => {
  const dark = getComputedStyle(document.body).backgroundColor !== 'rgb(228, 234, 236)';
  S.prefs.theme = dark ? 'light' : 'dark'; savePrefs(); applyTheme();
});
$('#lockbtn').addEventListener('click', () => lock());
document.addEventListener('submit', e => { if (e.target.id === 'lockform') { e.preventDefault(); onLockSubmit(e.target); } });
function loadScript(src) {
  return new Promise((ok, fail) => {
    if ([...document.scripts].some(s => s.src === src)) return ok();
    const s = Object.assign(document.createElement('script'), { src, onload: ok, onerror: fail });
    document.head.appendChild(s);
  });
}
window.addEventListener('hashchange', () => { if (location.hash.startsWith('#pair=')) { location.reload(); return; } const v = location.hash.slice(1); if (['pipeline', 'applications', 'waiting', 'summary'].includes(v)) { S.view = v; render(); } });
document.addEventListener('visibilitychange', () => { if (!document.hidden && S.token && !DEMO) loadRuns().then(() => { render(); watchRuns(); }); });

/* ---------- demo data (fictional, for previewing the layout only) ---------- */
const DEMO_DATA = {
  [FILES.applications]: { items: [
    { id: 'a-1', company: 'Northwind Aero', role: 'Electrical Integration Intern', industry: 'Aerospace', source: 'Career Expo', dateApplied: '2026-10-14', stage: 'Interview', status: 'In Progress', location: 'Denver, CO', portal: 'Greenhouse', contact: 'Recruiter screen done', nextStep: 'Panel interview Friday', notes: 'Asked about harness work', outreach: [{ id: 'o-1', name: 'Sample Engineer (integration)', channel: 'Email', handle: '', sentOn: '2026-10-10', followUpOn: '2026-10-17', status: 'Sent' }, { id: 'o-2', name: 'Sample Recruiter', channel: 'LinkedIn', handle: '', sentOn: '2026-10-11', followUpOn: '', status: 'Replied' }] },
    { id: 'a-2', company: 'Bluefin Motorsport', role: 'Electronics Intern', industry: 'Motorsports', source: 'LinkedIn', dateApplied: '2026-10-02', stage: 'Applied', status: 'In Progress', location: 'Charlotte, NC', portal: 'Workday', contact: '', nextStep: '', notes: '' },
    { id: 'a-3', company: 'Orbital Example Co', role: 'Avionics Test Intern', industry: 'Aerospace', source: '#careers', dateApplied: '2026-09-20', stage: 'Rejected', status: 'Rejected', location: 'Los Angeles, CA', portal: 'Lever', contact: '', nextStep: '', notes: 'Rejected 10/1' },
  ] },
  [FILES.waiting]: { items: [
    { id: 'w-1', company: 'Sample eVTOL', industry: 'Aerospace (eVTOL)', source: 'Claude research', notes: 'Past interns: battery, HV harness', appStatus: 'Not yet: apps open in November', lastChecked: '2026-10-21', careersUrl: 'https://example.com/careers', taskAdded: '' },
    { id: 'w-2', company: 'Demo Racing', industry: 'Motorsports', source: 'Career Expo', notes: '', appStatus: 'OPEN: 2027 engineering internship', lastChecked: '2026-10-21', careersUrl: '', taskAdded: 'Yes 10/21' },
  ] },
  [FILES.pipeline]: { items: [
    { id: 'p-1', dateFound: '2026-10-22', score: 88, company: 'Example Robotics', title: 'Hardware Systems Integration Intern', url: 'https://example.com/job/1', locations: ['Boston, MA'], terms: ['Summer 2027'], flags: [], reasons: ['Integration and test work', 'Small hardware team'] },
    { id: 'p-2', dateFound: '2026-10-22', score: 72, company: 'Sample Launch', title: 'Avionics Electrical Intern', url: 'https://example.com/job/2', locations: ['Austin, TX'], terms: ['Summer 2027'], flags: ['defense-adjacent'], reasons: ['Avionics harness match'] },
    { id: 'p-3', dateFound: '2026-10-21', score: null, heuristic: 31, company: 'Demo EV', title: 'Battery Engineering Intern', url: 'https://example.com/job/3', locations: ['Palo Alto, CA'], terms: ['Spring 2027'], flags: ['Spring 2027 only'], reasons: [] },
  ] },
  [FILES.status]: { items: {} },
  [FILES.control]: { paused: false, minScore: 55, minHeuristic: 15 },
  [FILES.options]: { industry: ['Aerospace', 'Automotive', 'Motorsports', 'Energy', 'Other'], source: ['#careers', 'LinkedIn', 'Career Expo', 'Referral', 'Pipeline', 'Other'], stage: ['Outreach', 'Emailed', 'Applied', 'Screening', 'Assessment', 'Interview', 'Technical Interview', 'Final Round', 'Offer', 'Rejected'], status: ['In Progress', 'Accepted', 'Rejected', 'Withdrawn', 'No Response'], portal: ['Greenhouse', 'Workday', 'Lever', 'Ashby', 'Other'] },
  [FILES.lastRun]: { date: '2026-10-22', finishedAt: '2026-10-22T12:43:00Z', mode: 'none', added: 3, stats: { fetched: 10991, new: 52 }, errors: [], trigger: 'schedule' },
};
const DEMO_PACKETS = {
  [packetName('p-1')]: {
    id: 'p-1', company: 'Example Robotics', title: 'Hardware Systems Integration Intern', url: 'https://example.com/job/1', builtAt: '2026-10-22T13:05:00Z', status: 'ready', jdSource: 'greenhouse', cost: 0.031,
    jd: 'Example Robotics builds warehouse robots. Interns design test fixtures, debug electro-mechanical issues, and write Python tools.',
    questions: [{ label: 'Why Example Robotics?' }],
    fit: { summary: 'Integration and validation work on the solar car maps directly to building test setups and debugging hardware.', gaps: ['Python test tooling is not shown on the resume'] },
    resume: { roles: { 'lhr-wrh': ['wrh-harness', 'wrh-mentor', 'wrh-smb'], 'lhr-pt': ['pt-protection', 'pt-enclosure'], 'voting-intern': ['vote-web'] }, projects: [{ id: 'daq', bullets: ['daq-design', 'daq-fab'] }, { id: 'aux24', bullets: ['aux-pcb', 'aux-frame'] }, { id: 'smb', bullets: ['smb-rev'] }], skillsOrder: ['sk-lab', 'sk-cad', 'sk-lang'], includeRoles: ['lhr-wrh', 'lhr-pt'] },
    coverLetter: 'Sample cover letter paragraph one.\n\nParagraph two with a concrete project.\n\nLeo Block',
    answers: [{ question: 'Why Example Robotics?', answer: 'Sample answer.' }],
    outreach: { lookFor: ['hardware test engineers', 'university recruiter'], emailSubject: 'UT Austin harness lead, applied to HW Integration', emailBody: 'Hi [Name],\n\nSample email.\n\nLeo', recruiterEmailBody: 'Hi [Name],\n\nShort note.\n\nLeo', linkedinNote: 'Hi [Name], sample note.' },
    check: { unsupported: [{ where: 'coverLetter', text: 'I wrote Python test tools.', why: 'Python test tooling is not in the resume' }] },
  },
};
DEMO_DATA[FILES.resume] = { name: 'Sample Name', contact: [{ text: 'sample@example.com' }, { text: 'example.com' }], education: [{ school: 'Sample University', degree: 'B.S. Electrical Engineering', date: 'May 2028', coursework: 'Circuits, Signals' }],
  experience: [{ id: 'lhr', org: 'Sample Racing Team', date: '2025 – Present', roles: [
    { id: 'lhr-wrh', title: 'Harness Lead', date: '2026 – Present', bullets: [{ id: 'wrh-harness', text: 'Sample bullet about harness design.' }, { id: 'wrh-smb', text: 'Sample bullet about a BMS board.' }, { id: 'wrh-mentor', text: 'Sample bullet about mentoring.' }] },
    { id: 'lhr-pt', title: 'Powertrain Engineer', date: '2025 – 2026', bullets: [{ id: 'pt-protection', text: 'Sample bullet about protection circuits.' }, { id: 'pt-enclosure', text: 'Sample bullet about enclosures.' }] }] },
    { id: 'voting', org: 'Sample Org', date: '2023', roles: [{ id: 'voting-intern', title: 'Intern', date: '', bullets: [{ id: 'vote-web', text: 'Sample web bullet.' }] }] }],
  projects: [{ id: 'daq', title: 'Sample Harness Project', date: '2026', link: 'https://example.com', bullets: [{ id: 'daq-design', text: 'Sample design bullet.' }, { id: 'daq-fab', text: 'Sample fabrication bullet.' }] },
    { id: 'aux24', title: 'Sample Battery Project', date: '2025', bullets: [{ id: 'aux-pcb', text: 'Sample PCB bullet.' }, { id: 'aux-frame', text: 'Sample frame bullet.' }] },
    { id: 'smb', title: 'Sample Board', date: '2026', bullets: [{ id: 'smb-rev', text: 'Sample board bullet.' }] }],
  skills: [{ id: 'sk-cad', label: 'CAD', items: ['KiCad'] }, { id: 'sk-lang', label: 'Languages', items: ['C'] }, { id: 'sk-lab', label: 'Lab', items: ['Oscilloscope'] }] };
DEMO_DATA[FILES.status].items['p-1'] = { status: 'Approved' };
DEMO_DATA[FILES.packetReq] = { items: {} };
function demoRead(path) { return Promise.resolve({ data: structuredClone(DEMO_DATA[path] ?? null), sha: 'demo' }); }
function demoUpdate(path, mutate) { DEMO_DATA[path] = mutate(structuredClone(DEMO_DATA[path] ?? {})); return Promise.resolve(structuredClone(DEMO_DATA[path])); }

/* ---------- start ---------- */
applyTheme();
{ const v = location.hash.slice(1); if (['pipeline', 'applications', 'waiting', 'summary'].includes(v)) S.view = v; }
{
  const m = location.hash.match(/^#pair=([\w.-]+)$/);
  if (m) { S.pairBlob = m[1]; showLock('pair'); }
  else if (DEMO || S.token) showApp();
  else lock();
}
