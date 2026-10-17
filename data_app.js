/* ================= ESP32 AUDIT — frontend ================= */
'use strict';

const S = {
  ws: null, ok: false, view: 'dashboard',
  status: {}, packets: [], aps: [], probes: [], stas: [], creds: [],
  target: null, sniffing: false, paused: false
};

/* ---------- ws ---------- */
function connect() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  S.ws = ws;
  ws.onopen = () => { S.ok = true; log(1, 'WebSocket Connected!'); };
  ws.onclose = () => {
    S.ok = false;
    log(2, 'Connection lost (Channel Switch?). Reconnecting WiFi...');
    setTimeout(connect, 1500);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = e => {
    let d; try { d = JSON.parse(e.data); } catch { return; }
    handle(d);
  };
}

function send(cmd, a = {}) {
  if (!S.ok) return;
  S.ws.send(JSON.stringify({ cmd, a }));
}

/* ---------- inbound ---------- */
function handle(d) {
  switch (d.evt) {
    case 'status':  S.status = d; paintTop(); if (S.view === 'dashboard') paint(); break;
    case 'log':     (d.l || []).forEach(x => log(x.l, x.m, x.t)); break;
    case 'pkt':     S.packets = d.p || []; if (S.view === 'analyzer') paint(); break;
    case 'aps':     S.aps = d.a || [];     if (['scanner','recon','dashboard'].includes(S.view)) paint(); break;
    case 'sta':     S.stas = d.c || [];    if (S.view === 'recon') paint(); break;
    case 'prb':     S.probes = d.p || [];  if (S.view === 'karma') paint(); break;
    case 'creds':   S.creds = d.c || [];   if (S.view === 'creds') paint(); break;
  }
}

/* ---------- terminal ---------- */
const TERM = [];
function log(lvl, msg, ts) {
  const t = ts || Date.now() % 100000;
  TERM.push({ lvl, msg, t });
  if (TERM.length > 300) TERM.shift();
  const el = document.getElementById('term');
  if (!el) return;
  const d = document.createElement('div');
  d.innerHTML = `<span class="t">[${fmtT(t)}]</span><span class="l${lvl}">${esc(msg)}</span>`;
  el.appendChild(d);
  while (el.children.length > 300) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
}
function fmtT(ms) {
  const s = Math.floor(ms / 1000);
  return `${String(Math.floor(s/3600)).padStart(2,'0')}:${String(Math.floor(s/60)%60).padStart(2,'0')}:${String(s%60).padStart(2,'0')}`;
}
const esc = s => String(s).replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));

/* ---------- topbar ---------- */
function paintTop() {
  const s = S.status;
  const u = document.getElementById('uptime'); if (u) u.textContent = fmtT((s.up||0)*1000);
  const r = document.getElementById('ram');
  if (r) r.textContent = (100 - (s.heapPct||0)) + '%';
  const sd = document.getElementById('sd');
  if (sd) sd.textContent = s.sd ? (s.sdFree + 'MB') : '--';
  const p = document.getElementById('sdpill');
  if (p) p.classList.toggle('on', !!s.sd);
}

/* ---------- views ---------- */
const TITLES = {
  dashboard:'Status Overview', analyzer:'Packet Analyzer', scanner:'Scanner & Sniff',
  recon:'Recon (Airodump)', eviltwin:'Evil Twin Attack', karma:'Karma Attack',
  deauther:'Deauther', blesniff:'BLE Sniffer', blespam:'BLE Spam Attack',
  target:'Target Connection', hostdisc:'Host Discovery', portscan:'Port Scanner',
  handshake:'Captured Handshake', creds:'Captured Creds', config:'Configuration'
};

const V = {};

/* ---------- dashboard ---------- */
V.dashboard = () => {
  const s = S.status, t = s.tSet ? s : null;
  return `
  <h2>Dashboard</h2>
  <div class="grid4" style="margin-bottom:14px">
    ${['EVIL TWIN|evil','DEAUTHER|deauth','KARMA|karma'].map(x=>{
      const [n,k]=x.split('|');
      return `<div class="kpi b-g"><div class="k">${n}</div>
        <div class="v ${s[k]?'g':'dim'}">${s[k]?'ACTIVE':'INACTIVE'}</div></div>`;}).join('')}
  </div>
  <div class="grid4">
    <div class="kpi b-g">
      <div class="k">PRIMARY TARGET INFO</div>
      <div class="v">${t?esc(t.tSsid):'No Target'}</div>
      <div class="tiny dim" style="margin-top:8px">MAC ${t?t.tMac:'--:--:--:--:--:--'}</div>
      <div class="tiny dim">CHANNEL ${t?t.tCh:'--'} &nbsp; RSSI ${t?t.tRssi:'--'} dBm</div>
    </div>
    <div class="kpi b-r">
      <div class="k">INTELLIGENCE &amp; CAPTURE</div>
      <div class="tiny dim" style="margin-top:8px">WPA Handshake</div>
      <div class="v ${s.hs?'g':''}">${s.hs||0}</div>
      <div class="tiny dim">CLIENTS ${s.sta||0} &nbsp; NETWORKS ${s.ap||0}</div>
    </div>
    <div class="kpi b-g">
      <div class="k">PACKET INJECTION HEALTH</div>
      <div class="v g">${s.tx||0}<span class="tiny dim"> SENT</span></div>
      <div class="v r">${s.drop||0}<span class="tiny dim"> DROPPED</span></div>
      <div class="v b">${s.pps||0}<span class="tiny dim"> PPS</span></div>
    </div>
    <div class="kpi b-b">
      <div class="k">STA NETWORK &amp; DISCOVERY</div>
      <div class="v ${s.uplink?'g':'dim'}">${s.uplink?'Online':'No Network'}</div>
      <div class="tiny dim">IP ${s.ip||'--'}</div>
      <div class="tiny dim">CH ${s.ch||1} &nbsp; RX ${s.rx||0}</div>
    </div>
  </div>`;
};

/* ---------- analyzer ---------- */
V.analyzer = () => {
  const rows = S.packets.slice(-120).map(p => `
    <tr>
      <td>${p.ch}</td>
      <td class="${p.rssi>-60?'':''}" style="color:${p.rssi>-55?'#00ff88':p.rssi>-75?'#ffb020':'#ff4d4d'}">${p.rssi}</td>
      <td>${['MGMT','CTRL','DATA'][p.ty]||'?'}</td>
      <td><span class="tag ${p.ty===0?'b':'g'}">${stName(p.st)}</span></td>
      <td>${p.src}</td><td>${p.dst}</td><td>${p.len}</td>
      <td class="dim">${esc(p.info)}</td>
    </tr>`).join('');
  return `
  <h2>Live Packet Analyzer</h2>
  <div class="card">
    <h3>Capture Configuration</h3>
    <div class="row">
      <div class="col"><label>Frequency</label>
        <select id="fch">${[...Array(13)].map((_,i)=>`<option>CH ${i+1}</option>`).join('')}</select></div>
      <div class="col"><label>Hop</label>
        <select id="fhop"><option value="1">HOP</option><option value="0">LOCK</option></select></div>
      <div class="col"><label>Main Frame Type</label>
        <select id="fty">
          <option value="255">ALL</option><option value="0">MANAGEMENT</option>
          <option value="1">CONTROL</option><option value="2">DATA</option>
        </select></div>
      <div class="col"><label>Subtype Filter</label>
        <select id="fst">
          <option value="255">All</option><option value="8">BEACON</option>
          <option value="4">PROBE-REQ</option><option value="5">PROBE-RESP</option>
          <option value="11">AUTH</option><option value="12">DEAUTH</option>
        </select></div>
    </div>
    <h3>Display Filters</h3>
    <div class="row">
      <div class="col"><label>Source MAC</label><input id="fsrc" placeholder="AA:BB:.."></div>
      <div class="col"><label>Dest MAC</label><input id="fdst" placeholder="AA:BB:.."></div>
      <div class="col"><label>SSID / Info</label><input id="fssid" placeholder="marvi"></div>
      <div class="col"><label>Min RSSI</label><input id="frssi" type="number" value="-95"></div>
    </div>
    <div class="row" style="margin-top:14px">
      <button class="btn green" onclick="startSniff()">▶ START</button>
      <button class="btn red" onclick="send('sniff.stop')">■ STOP</button>
      <button class="btn" onclick="S.paused=!S.paused;send('sniff.pause',{on:S.paused})">PAUSE VIEW</button>
      <button class="btn" onclick="S.packets=[];send('sniff.clear')">CLEAR</button>
      <span class="pill" style="align-self:center">Rx:${S.status.rx||0} | Shown:${S.packets.length}</span>
    </div>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <table><thead><tr>
      <th>CH</th><th>DBM</th><th>TYPE</th><th>SUBTYPE</th><th>SOURCE</th>
      <th>DESTINATION</th><th>LEN</th><th>INFO</th>
    </tr></thead><tbody>${rows}</tbody></table>
  </div>`;
};

function startSniff() {
  const ch = parseInt((document.getElementById('fch').value||'CH 1').split(' ')[1]);
  send('sniff.start', {
    ch, hop: document.getElementById('fhop').value === '1',
    ftype: +document.getElementById('fty').value,
    stype: +document.getElementById('fst').value,
    rssi:  +document.getElementById('frssi').value
  });
  send('sniff.filters', {
    src: document.getElementById('fsrc').value,
    dst: document.getElementById('fdst').value,
    ssid: document.getElementById('fssid').value,
    rssi: +document.getElementById('frssi').value
  });
}

const ST = ['ASSOC-REQ','ASSOC-RESP','REASSOC-REQ','REASSOC-RESP','PROBE-REQ','PROBE-RESP',
            'TIMING-ADV','RES','BEACON','ATIM','DISASSOC','AUTH','DEAUTH','ACTION','ACT-NOACK','RES'];
const stName = i => ST[i] || ('SUB' + i);

/* ---------- scanner ---------- */
V.scanner = () => `
  <h2>WiFi Scanner</h2>
  <div class="card">
    <p class="dim">Scan for nearby Access Points to select a target.</p>
    <button class="btn green" style="margin-top:12px" onclick="send('scan.start')">START SCAN</button>
  </div>
  <div class="card" style="padding:0;overflow:hidden">
    <table><thead><tr><th>SSID</th><th>RSSI</th><th>CH</th><th>BSSID</th><th>SEC</th><th>ACTION</th></tr></thead>
    <tbody>${S.aps.map(a=>`
      <tr><td><b>${esc(a.ssid)}</b></td>
      <td style="color:${a.rssi>-55?'#00ff88':a.rssi>-75?'#ffb020':'#ff4d4d'}">${a.rssi}</td>
      <td>${a.ch}</td><td>${a.bssid}</td>
      <td class="dim">${['OPEN','WEP','WPA','WPA2','WPA_WPA2_PSK','WPA3'][a.auth]||'?'}</td>
      <td><button class="btn green sm" onclick="pick('${a.bssid}','${esc(a.ssid)}',${a.ch},${a.rssi},${a.auth})">TARGET</button></td></tr>`).join('')}
    </tbody></table>
  </div>`;

function pick(mac, ssid, ch, rssi, auth) {
  S.target = { mac, ssid, ch, rssi, auth };
  send('target.set', { mac, ssid, ch, rssi, auth });
  log(1, `Target locked: ${ssid}`);
}

/* ---------- recon ---------- */
V.recon = () => `
  <h2>Airodump — AP / Station Recon</h2>
  <div class="card"><div class="row">
    <button class="btn green" onclick="send('scan.start')">RESCAN</button>
    <button class="btn" onclick="send('sniff.start',{ch:1,hop:true,ftype:255,stype:255,rssi:-95})">PASSIVE SCAN</button>
  </div></div>
  <h3>Access Points (${S.aps.length})</h3>
  <div class="card" style="padding:0;overflow:hidden"><table>
    <thead><tr><th>BSSID</th><th>CH</th><th>RSSI</th><th>SEC</th><th>SSID</th></tr></thead>
    <tbody>${S.aps.map(a=>`<tr><td>${a.bssid}</td><td>${a.ch}</td><td>${a.rssi}</td>
      <td class="dim">${a.auth}</td><td><b>${esc(a.ssid)}</b></td></tr>`).join('')}</tbody></table></div>
  <h3>Stations (${S.stas.length})</h3>
  <div class="card" style="padding:0;overflow:hidden"><table>
    <thead><tr><th>STATION MAC</th><th>BSSID</th><th>SSID</th><th>RSSI</th></tr></thead>
    <tbody>${S.stas.map(c=>`<tr><td>${c.mac}</td><td>${c.bssid}</td><td>${esc(c.ssid)}</td><td>${c.rssi}</td></tr>`).join('')}</tbody></table></div>`;

/* ---------- evil twin ---------- */
V.eviltwin = () => {
  const t = S.target;
  return `
  <h2>Evil Twin Attack</h2>
  <div class="card">
    <h3>Attack Scenario</h3>
    <select id="esc"><option>Firmware Upgrade</option><option>Router Login</option>
      <option>WiFi Password Expired</option><option>Captive Portal</option></select>
    <h3>Target Details</h3>
    <div class="info">${t ? `<b>${esc(t.ssid)}</b><br><span class="tiny">${t.mac} · CH ${t.ch}</span>`
      : 'No target — go to Scanner &amp; Sniff and press TARGET.'}</div>
    <div class="row">
      <button class="btn red" onclick="evilGo()">LAUNCH ATTACK</button>
      <button class="btn" onclick="send('evil.stop')">TERMINATE</button>
    </div>
    <p class="warn" style="margin-top:14px">Clients connecting to the twin will see the captive
    portal. Submitted passwords land in <b>Captured Creds</b>.</p>
  </div>`;
};

function evilGo() {
  if (!S.target) return log(2, 'Select a target first.');
  send('evil.start', { ssid: S.target.ssid, ch: S.target.ch });
}

/* ---------- karma ---------- */
V.karma = () => `
  <h2>Karma Probe Scanner</h2>
  <div class="card">
    <h3>1. Phishing Scenario</h3>
    <select><option>Firmware Upgrade</option><option>Router Login</option></select>
    <h3>2. Scan for devices probing for known networks.</h3>
    <div class="row">
      <button class="btn green" onclick="send('karma.start')">SCAN PROBES</button>
      <button class="btn" onclick="send('karma.stop')">STOP SCAN</button>
      <button class="btn" onclick="send('karma.clear')">CLEAR</button>
    </div>
  </div>
  <h3>Detected Probes (${S.probes.length})</h3>
  <div class="card" style="padding:0;overflow:hidden"><table>
    <thead><tr><th>VICTIM MAC</th><th>TARGET SSID</th><th>RSSI</th><th>CH</th><th>ACTION</th></tr></thead>
    <tbody>${S.probes.map((p,i)=>`<tr><td>${p.mac}</td><td><b>${esc(p.ssid)}</b></td>
      <td>${p.rssi}</td><td>${p.ch}</td>
      <td><button class="btn red sm" onclick="send('karma.attack',{idx:${i}})">ATTACK</button></td></tr>`).join('')}
    </tbody></table></div>`;

/* ---------- deauther ---------- */
V.deauther = () => {
  const t = S.target;
  return `
  <h2>Deauthentication Attack</h2>
  <div class="card">
    <h3>Target Mode</h3>
    <select id="dmode">
      <option value="1">Single Target (Selected SSID)</option>
      <option value="0">Broadcast to Selected AP</option>
      <option value="2">All Networks</option>
      <option value="3">Beacon Abuse (Regulatory)</option>
    </select>
    <div class="card" style="margin-top:14px;border-style:dashed">
      <div class="tiny" style="color:var(--red);letter-spacing:1.4px">CURRENT TARGET</div>
      <div style="font-size:17px;font-weight:700;color:#fff;margin:6px 0">${t?esc(t.ssid):'-- None --'}</div>
      <div class="tiny dim">CHANNEL ${t?t.ch:'--'}</div>
    </div>
    <h3>Attack Type</h3>
    <select id="dtype">
      <option value="0">Standard Deauth (reason 2)</option>
      <option value="1">Deauth — STA leaving (reason 3)</option>
      <option value="2">Deauth — inactivity (reason 4)</option>
      <option value="3">Disassoc (reason 5)</option>
      <option value="4">Class 3 frame (reason 7)</option>
    </select>
    <div class="bad" style="margin-top:12px"><b>WARNING:</b> this will disconnect clients
      from the selected Access Point.</div>
    <div class="row" style="margin-top:12px">
      <button class="btn red" onclick="send('deauth.start',{mode:+document.getElementById('dmode').value,type:+document.getElementById('dtype').value,burst:6,period:100})">START ATTACK</button>
      <button class="btn" onclick="send('deauth.stop')">STOP</button>
      <span class="pill" style="align-self:center">SENT ${S.status.tx||0}</span>
    </div>
  </div>`;
};

/* ---------- ble ---------- */
V.blesniff = () => `
  <h2>BLE Sniffer</h2>
  <div class="card">
    <div class="row">
      <button class="btn green" onclick="send('ble.scan')">START SCAN (3s)</button>
      <span class="pill" style="align-self:center">Found ${S.status.bleDevs||0}</span>
    </div>
  </div>
  <div class="card"><p class="dim tiny">BLE scan results are streamed in the log console below.
  Use it to map nearby beacons, trackers and wearables.</p></div>`;

V.blespam = () => `
  <h2>BLE Spam Attack</h2>
  <div class="card">
    <h3>Payload</h3>
    <select id="bsm">
      <option value="0">Apple Continuity (iOS popups)</option>
      <option value="1">Samsung Fast Pair</option>
      <option value="2">Google Fast Pair</option>
      <option value="3">Custom names (SPAM-xx)</option>
    </select>
    <div class="row" style="margin-top:12px">
      <button class="btn green" onclick="send('ble.spam',{mode:+document.getElementById('bsm').value})">START SPAM</button>
      <button class="btn" onclick="send('ble.stop')">STOP</button>
    </div>
  </div>`;

/* ---------- net ---------- */
V.target = () => `
  <h2>Target Connection</h2>
  <div class="card">
    <h3>Uplink</h3>
    <div class="info">Status: <b>${S.status.uplink?'CONNECTED':'OFFLINE'}</b> · IP ${S.status.ip||'--'}</div>
    <h3>Ping</h3>
    <div class="row">
      <div class="col"><label>Host</label><input id="ph" value="1.1.1.1"></div>
      <div class="col"><label>Count</label><input id="pc" type="number" value="4"></div>
      <button class="btn green" style="align-self:flex-end" onclick="send('net.ping',{host:document.getElementById('ph').value,count:+document.getElementById('pc').value})">PING</button>
    </div>
  </div>`;

V.hostdisc = () => `
  <h2>Host Discovery</h2>
  <div class="card">
    <button class="btn green" onclick="send('net.hosts')">SCAN SUBNET</button>
    <p class="warn" style="margin-top:12px">Requires an uplink network. Sweeps /24 for live hosts.</p>
  </div>`;

V.portscan = () => `
  <h2>Port Scanner</h2>
  <div class="card">
    <div class="row">
      <div class="col"><label>Host</label><input id="pip" value="192.168.4.1"></div>
      <div class="col"><label>From</label><input id="pfrom" type="number" value="1"></div>
      <div class="col"><label>To</label><input id="pto" type="number" value="1024"></div>
      <button class="btn green" style="align-self:flex-end"
        onclick="send('net.ports',{ip:document.getElementById('pip').value,from:+document.getElementById('pfrom').value,to:+document.getElementById('pto').value})">SCAN</button>
    </div>
  </div>`;

/* ---------- system ---------- */
V.handshake = () => `
  <h2>Captured Handshakes</h2>
  <div class="card">
    <div class="info">${S.status.hs||0} handshake file(s) stored on SD under /handshakes/.
    Download them and crack with aircrack-ng / hashcat.</div>
    <button class="btn" onclick="location.href='/api/status'">REFRESH</button>
  </div>`;

V.creds = () => `
  <h2>Captured Credentials</h2>
  <div class="card" style="padding:0;overflow:hidden"><table>
    <thead><tr><th>SSID</th><th>USER</th><th>PASSWORD</th></tr></thead>
    <tbody>${S.creds.map(c=>`<tr><td>${esc(c.ssid)}</td><td>${esc(c.user)}</td>
      <td style="color:var(--acc2)"><b>${esc(c.pass)}</b></td></tr>`).join('')}</tbody></table></div>
  <button class="btn red" onclick="send('creds.clear')">CLEAR ALL</button>`;

V.config = () => `
  <h2>Configuration</h2>
  <div class="card">
    <h3>System</h3>
    <div class="info">Heap free: ${(S.status.heap/1024|0)} KB · Uptime ${fmtT((S.status.up||0)*1000)}</div>
    <div class="row" style="margin-top:12px">
      <button class="btn" onclick="send('sys.reboot')">REBOOT</button>
      <button class="btn red" onclick="fetch('/api/reset').then(()=>log(1,'Buffers cleared'))">CLEAR BUFFERS</button>
    </div>
  </div>
  <div class="card">
    <h3>LittleFS</h3>
    <div id="fslist" class="dim tiny">loading...</div>
  </div>`;

/* ---------- router ---------- */
function paint() {
  const el = document.getElementById('view');
  document.getElementById('title').textContent = TITLES[S.view];
  el.innerHTML = (V[S.view] || (() => '<p>WIP</p>'))();
  if (S.view === 'config') {
    fetch('/api/fs').then(r=>r.json()).then(l => {
      document.getElementById('fslist').innerHTML =
        l.map(f=>`${esc(f.n)} <span class="dim">(${f.s}B)</span>
          <button class="btn sm" onclick="send('fs.delete',{path:'/${f.n}'});setTimeout(paint,400)">DEL</button>`).join('<br>')
        || 'empty';
    });
  }
}

function go(v) {
  S.view = v;
  document.querySelectorAll('nav a').forEach(a => a.classList.toggle('on', a.dataset.v === v));
  paint();
}

document.querySelectorAll('nav a').forEach(a => a.onclick = () => go(a.dataset.v));

/* ---------- boot ---------- */
connect();
go('dashboard');
setInterval(() => { if (S.ok) send('sys.status'); }, 1000);