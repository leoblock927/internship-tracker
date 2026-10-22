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
};
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
  await loadRuns();
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
  $('#c-applications').textContent = ` ${a}`;
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
  if (active) { st.className = 'state busy'; st.textContent = `${active.name.replace('Daily internship ', '').replace('Detect job boards', 'Detecting boards')} ${active.status === 'queued' ? 'queued' : 'running'}`; }
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
    $('#lastrun').innerHTML = `${esc(when ? when.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ', ' + when.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : lr.date)} <small>${failed ? '<span style="color:var(--batt)">last run failed</span>' : esc(lr.mode === 'paused' ? 'skipped (paused)' : (lr.trigger === 'schedule' ? 'scheduled' : 'manual'))}</small>`;
    const s = lr.stats || {};
    $('#lastfound').innerHTML = lr.mode === 'paused' ? '<small>nothing, paused</small>' : `${esc(lr.added ?? 0)} added <small>of ${esc(s.new ?? 0)} new, ${esc((s.fetched ?? 0).toLocaleString())} checked${lr.errors?.length ? `, <span style="color:var(--batt)">${lr.errors.length} errors</span>` : ''}</small>`;
  } else {
    $('#lastrun').innerHTML = '<small>No runs yet</small>';
    $('#lastfound').innerHTML = '<small>...</small>';
  }
}

function toolbar(title, sub, extra = '') {
  return `<div class="toolbar"><h2>${esc(title)}<small>${esc(sub)}</small></h2>
    <input class="search" id="search" type="search" placeholder="Search" value="${esc(S.q)}" aria-label="Search">${extra}</div>`;
}
function seg(key, values) {
  return `<div class="seg" role="group">${values.map(v => `<button type="button" data-act="seg" data-key="${key}" data-val="${esc(v)}" aria-pressed="${S.prefs[key] === v}">${esc(v)}</button>`).join('')}</div>`;
}

function viewPipeline() {
  const all = S.data.pipeline.items;
  const f = S.prefs.pipeFilter;
  const list = all
    .filter(j => f === 'All' || pipeStatus(j.id) === f)
    .filter(j => matchesQ(j.company, j.title, (j.locations || []).join(' '), (j.flags || []).join(' ')))
    .sort((a, b) => (b.dateFound || '').localeCompare(a.dateFound || '') || (scoreOf(b) ?? 0) - (scoreOf(a) ?? 0));
  const n = s => all.filter(j => pipeStatus(j.id) === s).length;
  const head = toolbar('Pipeline', `${n('New')} new, ${n('Approved')} approved`, seg('pipeFilter', ['New', 'Approved', 'Applied', 'Skipped', 'All']));
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
  const acts = st === 'New'
    ? `<button class="btn small go" data-act="pipe-approve" data-id="${esc(j.id)}">Approve</button>
       <button class="btn small" data-act="pipe-applied" data-id="${esc(j.id)}">Applied</button>
       <button class="btn small" data-act="pipe-skip" data-id="${esc(j.id)}">Skip</button>`
    : st === 'Approved'
      ? `<button class="btn small primary" data-act="pipe-applied" data-id="${esc(j.id)}">Mark applied</button>
         <button class="btn small" data-act="pipe-undo" data-id="${esc(j.id)}">Undo</button>`
      : `<button class="btn small" data-act="pipe-undo" data-id="${esc(j.id)}">Move back to New</button>`;
  return `<article class="card" style="--wire:${wireVar(scoreWire(j))}">
    <div class="score">${sc == null ? '-' : (j.score == null ? '~' : '') + esc(sc)}<small>${j.score == null ? 'keyword' : 'fit'}</small></div>
    <div>
      <h3>${url ? `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(j.title)}</a>` : esc(j.title)}</h3>
      <div class="meta"><b>${esc(j.company)}</b> · ${esc((j.locations || []).slice(0, 2).join('; ') || 'Location not listed')} · found ${esc(j.dateFound || '')}</div>
      ${(j.reasons || []).length ? `<ul class="reasons">${j.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      <div class="chips">${stChip}${terms}${flags}</div>
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
    .filter(a => f === 'All' || (f === 'Follow up' ? !!a.nextStep && a.status === 'In Progress' : a.status === f))
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
    <td data-l="Contact" class="clip">${esc(a.contact)}</td>
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
    <div class="panels">
      <div class="panel"><h3>Applications per week</h3><div class="weeks">${weeks.map(w => `<div><b>${w.n || ''}</b><span class="b" style="height:${(w.n / wmax) * 100}%"></span>${w.start.getMonth() + 1}/${w.start.getDate()}</div>`).join('')}</div></div>
      <div class="panel"><h3>By stage</h3>${bars(by('stage'), k => STAGE_WIRE[k], stageOrder.length ? stageOrder.concat(Object.keys(by('stage')).filter(k => !stageOrder.includes(k))) : null)}</div>
      <div class="panel"><h3>By industry</h3>${bars(by('industry'), () => 'auto')}</div>
      <div class="panel"><h3>By source</h3>${bars(by('source'), () => 'hv')}</div>
      <div class="panel"><h3>Follow-ups (${followups.length})</h3>${followups.length ? `<ul class="list">${followups.map(a => `<li><b>${esc(a.company)}</b>: ${esc(a.nextStep)}</li>`).join('')}</ul>` : '<p class="meta">Nothing waiting on you.</p>'}</div>
    </div>`;
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
function openDialog({ title, body, onSave, onDelete, saveLabel = 'Save' }) {
  const dlg = $('#dlg');
  $('#dlgform').innerHTML = `<div class="dhead"><h3>${esc(title)}</h3><button class="iconbtn" value="cancel" formnovalidate aria-label="Close">✕</button></div>
    <div class="dbody">${body}</div>
    <div class="dfoot">${onDelete ? '<button type="button" class="btn danger left" id="dlgdel">Delete</button>' : ''}<button class="btn" value="cancel" formnovalidate>Cancel</button><button class="btn primary" value="save" id="dlgsave">${esc(saveLabel)}</button></div>`;
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
  dlg.querySelector('input, select, textarea')?.focus();
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
  async 'pipe-approve'(el) { await setPipeStatus(el.dataset.id, 'Approved'); render(); toast('Approved.'); },
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
    openDialog({ title: 'Add application', body: appForm({}), onSave: async fd => { await addApplication(pickApp(fd), 'add'); render(); toast('Added.'); } });
  },
  async 'app-edit'(el) {
    const a = S.data.applications.items.find(x => x.id === el.dataset.id);
    if (!a) return;
    openDialog({
      title: `${a.company}`,
      body: appForm(a),
      onSave: async fd => {
        S.data.applications = await updateFile(FILES.applications, d => ({ ...d, items: d.items.map(x => (x.id === a.id ? { ...x, ...pickApp(fd) } : x)) }), `Tracker: update ${a.company}`);
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
    { id: 'a-1', company: 'Northwind Aero', role: 'Electrical Integration Intern', industry: 'Aerospace', source: 'Career Expo', dateApplied: '2026-10-14', stage: 'Interview', status: 'In Progress', location: 'Denver, CO', portal: 'Greenhouse', contact: 'Recruiter screen done', nextStep: 'Panel interview Friday', notes: 'Asked about harness work' },
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
