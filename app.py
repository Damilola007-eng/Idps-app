from flask import Flask, request, redirect, session, jsonify, render_template_string, Response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import random
import time
import threading
import csv
import io

app = Flask(__name__)
app.secret_key = os.environ.get("IDPS_SECRET_KEY", os.urandom(24).hex())

# ================= DATABASE =================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    created_at TEXT
)
""")
conn.commit()

# ================= IDS DATA (in-memory, thread-safe) =================

data_lock = threading.Lock()
packet_counts = []
timestamps = []
attacks = []          # list of dicts: id, ip, attack, severity, time, city, country, lat, lon, ack
next_event_id = 1

ATTACK_TYPES = ["Port Scan", "SYN Flood", "Brute Force", "DDoS Probe", "ARP Spoof", "DNS Tunneling"]

SEVERITY_MAP = {
    "Port Scan": "low",
    "ARP Spoof": "medium",
    "DNS Tunneling": "medium",
    "Brute Force": "high",
    "SYN Flood": "high",
    "DDoS Probe": "critical",
}

SEVERITY_COLOR = {
    "low": "#00E5FF",
    "medium": "#FFD400",
    "high": "#FF8A00",
    "critical": "#FF3B5C",
}

GEO_LOCATIONS = [
    {"city": "Lagos", "country": "Nigeria", "lat": 6.5244, "lon": 3.3792},
    {"city": "Moscow", "country": "Russia", "lat": 55.7558, "lon": 37.6173},
    {"city": "Beijing", "country": "China", "lat": 39.9042, "lon": 116.4074},
    {"city": "Sao Paulo", "country": "Brazil", "lat": -23.5505, "lon": -46.6333},
    {"city": "Mumbai", "country": "India", "lat": 19.0760, "lon": 72.8777},
    {"city": "Berlin", "country": "Germany", "lat": 52.5200, "lon": 13.4050},
    {"city": "New York", "country": "USA", "lat": 40.7128, "lon": -74.0060},
    {"city": "Tokyo", "country": "Japan", "lat": 35.6895, "lon": 139.6917},
    {"city": "London", "country": "UK", "lat": 51.5074, "lon": -0.1278},
    {"city": "Sydney", "country": "Australia", "lat": -33.8688, "lon": 151.2093},
]

BASE_LAT = 6.5244
BASE_LON = 3.3792

# ---- Simulator runtime controls ----
sim_lock = threading.Lock()
sim_state = {"paused": False, "speed": 1.0}  # speed multiplier: higher = faster events
blocked_ips = set()
manual_blocked_ips = set()
PREVENTION_ENABLED = True
AUTO_BLOCK_SEVERITY = ["high","critical"]


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def record_event(ip, attack):
    global next_event_id
    geo = random.choice(GEO_LOCATIONS)
    now = time.strftime("%H:%M:%S")
    with data_lock:
        event = {
            "id": next_event_id,
            "ip": ip,
            "attack": attack,
            "severity": SEVERITY_MAP.get(attack, "low"),
            "time": now,
            "city": geo["city"],
            "country": geo["country"],
            "lat": geo["lat"] + (random.random() - 0.5) * 4,
            "lon": geo["lon"] + (random.random() - 0.5) * 4,
            "ack": False,
            "blocked": False,
        }
        next_event_id += 1

        if PREVENTION_ENABLED and event["severity"] in AUTO_BLOCK_SEVERITY:
            blocked_ips.add(ip)
            event["blocked"] = True

        attacks.append(event)
        timestamps.append(now)
        packet_counts.append(random.randint(1, 25))

        if len(attacks) > 60:
            attacks.pop(0)
        if len(packet_counts) > 20:
            packet_counts.pop(0)
        if len(timestamps) > 20:
            timestamps.pop(0)


# ================= TRAFFIC SIMULATOR =================
# Real raw-packet sniffing (scapy) needs root privileges and a live network
# interface, which isn't available in most hosting/dev environments. This
# simulator generates realistic-looking IDS events so the dashboard works
# out of the box, and can be paused/sped up from the Settings page.

def start_traffic_simulator():
    while True:
        with sim_lock:
            paused = sim_state["paused"]
            speed = sim_state["speed"]
        if paused:
            time.sleep(0.4)
            continue
        time.sleep(random.uniform(1.5, 4) / max(speed, 0.1))
        record_event(random_ip(), random.choice(ATTACK_TYPES))


# ================= SHARED UI: NAV + STYLES =================

BASE_CSS = """
*{box-sizing:border-box;}
body{
    margin:0;
    background:#020617;
    color:#e8f4ff;
    font-family:'Courier New', monospace;
}
a{color:inherit;}
.layout{
    display:flex;
    min-height:100vh;
}
.sidebar{
    width:230px;
    flex-shrink:0;
    background:#000;
    border-right:1px solid #0ff3;
    padding:22px 0;
    display:flex;
    flex-direction:column;
}
.brand{
    padding:0 20px 20px;
    font-size:15px;
    font-weight:bold;
    color:#0ff;
    letter-spacing:1px;
    border-bottom:1px solid #0ff2;
    margin-bottom:14px;
}
.brand small{
    display:block;
    color:#5a7c93;
    font-size:9px;
    margin-top:4px;
    letter-spacing:1px;
}
.navlink{
    display:flex;
    align-items:center;
    gap:10px;
    padding:12px 20px;
    text-decoration:none;
    color:#7fa8c0;
    font-size:12.5px;
    letter-spacing:0.5px;
    border-left:3px solid transparent;
    transition:0.2s;
}
.navlink:hover{
    background:#0a1a2a;
    color:#0ff;
}
.navlink.active{
    background:#0a1a2a;
    color:#0ff;
    border-left:3px solid #0ff;
}
.sidebar-foot{
    margin-top:auto;
    padding:16px 20px;
    border-top:1px solid #0ff2;
}
.user-pill{
    font-size:11px;
    color:#5a7c93;
    margin-bottom:8px;
}
.user-pill b{color:#0ff;}
.logout{
    display:block;
    text-align:center;
    text-decoration:none;
    color:#fff;
    background:#aa0022;
    padding:8px;
    border-radius:8px;
    font-size:11px;
    letter-spacing:0.5px;
}
.logout:hover{background:#cc0033;}

.main{
    flex:1;
    min-width:0;
}
.topbar{
    display:flex;
    justify-content:space-between;
    align-items:center;
    padding:18px 28px;
    background:#000;
    box-shadow:0 0 20px #0ff2;
}
.topbar h1{
    font-size:17px;
    margin:0;
    letter-spacing:1px;
}
.status{
    display:flex;
    align-items:center;
    gap:8px;
    font-size:11px;
    color:#0f8;
}
.dot{
    width:9px;height:9px;border-radius:50%;
    background:#0f0;
    animation:blink 1.2s infinite;
}
.dot.paused{background:#f55;animation:none;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:0.2;}}

.content{
    padding:24px 28px 60px;
}

.stats{
    display:grid;
    grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
    gap:16px;
    margin-bottom:22px;
}
.stat-card{
    background:#0a0f1c;
    border:1px solid #0ff3;
    border-radius:10px;
    padding:14px 18px;
    text-align:center;
}
.stat-card .val{font-size:26px;font-weight:bold;color:#0ff;}
.stat-card .lbl{font-size:10.5px;color:#089;letter-spacing:0.5px;}

.card{
    background:#0a0f1c;
    border:1px solid #0ff;
    border-radius:10px;
    padding:18px;
    margin-bottom:20px;
}
.card h3{margin-top:0;font-size:14px;}
.card p.desc{color:#5a7c93;font-size:12.5px;margin-top:-4px;}

.btn{
    padding:9px 16px;
    border:1px solid #0ff;
    background:#001018;
    color:#0ff;
    border-radius:8px;
    cursor:pointer;
    font-family:inherit;
    font-size:11.5px;
    letter-spacing:0.5px;
    transition:0.2s;
}
.btn:hover{background:#0ff;color:#000;box-shadow:0 0 15px #0ff;}
.btn.danger{border-color:#ff3b5c;color:#ff3b5c;}
.btn.danger:hover{background:#ff3b5c;color:#fff;}
.btn.ghost{background:transparent;}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:18px;}

input,select{
    width:100%;
    padding:10px;
    background:#0a0a0a;
    border:1px solid #0ff5;
    color:#fff;
    border-radius:8px;
    font-family:inherit;
    font-size:12.5px;
    outline:none;
    margin-bottom:10px;
}
input:focus,select:focus{border-color:#0ff;box-shadow:0 0 8px #0ff5;}
label{font-size:11px;color:#7fa8c0;letter-spacing:0.5px;}

table{width:100%;border-collapse:collapse;font-size:12px;}
th{text-align:left;color:#089;font-size:10.5px;letter-spacing:0.5px;padding:8px 6px;border-bottom:1px solid #0ff3;}
td{padding:8px 6px;border-bottom:1px solid #0ff1;}
.sev{padding:3px 8px;border-radius:6px;font-size:10px;font-weight:bold;letter-spacing:0.5px;}

.feed div.entry{
    border-bottom:1px solid #0ff2;
    padding:10px 6px;
    font-size:12px;
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:10px;
}
.feed .meta{color:#5a7c93;font-size:11px;}
.feed .ackbtn{
    font-size:10px;
    padding:5px 9px;
    border-radius:6px;
    border:1px solid #0ff5;
    background:transparent;
    color:#0ff;
    cursor:pointer;
}
.feed .ackbtn:hover{background:#0ff;color:#000;}
.feed .acked{opacity:0.4;}

.msg-banner{
    padding:10px 14px;
    border-radius:8px;
    font-size:12.5px;
    margin-bottom:16px;
}
.msg-ok{background:#0a2a1e;border:1px solid #00ff8a;color:#5f5;}
.msg-err{background:#2a0a14;border:1px solid #ff3b5c;color:#ff8a99;}

#map{height:380px;border-radius:8px;}
.toggle-row{display:flex;align-items:center;gap:10px;margin-bottom:16px;}
"""


def nav_html(active, user):
    links = [
        ("overview", "/dashboard", "&#128737;", "Overview"),
        ("chart", "/threats/chart", "&#128202;", "Threat Curve"),
        ("map", "/threats/map", "&#127757;", "Attack Map"),
        ("feed", "/threats/feed", "&#9888;", "Threat Feed"),
        ("blocked", "/blocked", "&#128683;", "Blocked Attackers"),
        ("settings", "/settings", "&#9881;", "Settings"),
    ]
    items = ""
    for key, url, icon, label in links:
        cls = "navlink active" if key == active else "navlink"
        items += f'<a class="{cls}" href="{url}">{icon} {label}</a>\n'
    return f"""
<div class="sidebar">
  <div class="brand">&#128737; IDPS CONSOLE<small>SECURE OPS TERMINAL</small></div>
  {items}
  <div class="sidebar-foot">
    <div class="user-pill">Signed in as <b>{user}</b></div>
    <a class="logout" href="/logout">LOGOUT</a>
  </div>
</div>
"""


def page_shell(active, user, title, status_label, content):
    return f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title} | IDPS</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
<style>{BASE_CSS}</style>
</head>
<body>
<div class="layout">
{nav_html(active, user)}
<div class="main">
<div class="topbar">
<h1>{title}</h1>
<div class="status"><span class="dot" id="topdot"></span> <span id="topstatus">{status_label}</span></div>
</div>
<div class="content">
{content}
</div>
</div>
</div>
</body>
</html>
"""


# ================= LOGIN PAGE =================

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>IDPS Login</title>
<style>
*{box-sizing:border-box;}
body{
    margin:0;
    overflow:hidden;
    background:#000;
    font-family:'Courier New', monospace;
    color:#0f0;
}
canvas#matrix{
    position:fixed;
    top:0;left:0;
    z-index:0;
}
.container{
    position:absolute;
    top:50%;
    left:50%;
    transform:translate(-50%,-50%);
    width:360px;
    background:rgba(0,0,0,0.85);
    border:1px solid #0ff;
    border-radius:14px;
    padding:32px;
    box-shadow:0 0 25px #0ff;
    animation:glow 2s infinite alternate;
    z-index:1;
}
@keyframes glow{
    from{box-shadow:0 0 10px #0ff;}
    to{box-shadow:0 0 30px #0ff;}
}
h2{
    text-align:center;
    color:#0ff;
    letter-spacing:1px;
    margin-top:0;
}
.sub{
    text-align:center;
    color:#0a8;
    font-size:12px;
    margin-bottom:20px;
}
input{
    width:100%;
    padding:12px;
    margin-top:10px;
    background:#0a0a0a;
    border:1px solid #0ff;
    color:#fff;
    border-radius:8px;
    font-family:inherit;
    outline:none;
}
input:focus{
    box-shadow:0 0 10px #0ff;
}
.btn-row{
    display:flex;
    gap:10px;
    margin-top:18px;
}
button{
    flex:1;
    padding:12px;
    border:none;
    border-radius:8px;
    color:#fff;
    cursor:pointer;
    font-family:inherit;
    font-weight:bold;
    letter-spacing:0.5px;
    transition:0.25s;
}
button.login{
    background:linear-gradient(45deg,#00ffff,#0044ff);
}
button.register{
    background:linear-gradient(45deg,#003322,#00aa55);
}
button:hover{
    transform:scale(1.05);
    box-shadow:0 0 20px #0ff;
}
button:active{
    transform:scale(0.97);
}
.msg{
    text-align:center;
    margin-top:16px;
    min-height:18px;
    color:{{ "#5f5" if ok else "orange" }};
    font-size:13px;
}
.badge{
    display:flex;
    justify-content:center;
    gap:6px;
    margin-top:14px;
    font-size:11px;
    color:#066;
}
.dot{
    width:8px;height:8px;border-radius:50%;
    background:#0f0;
    animation:blink 1.2s infinite;
}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:0.2;}}
</style>
</head>
<body>

<canvas id="matrix"></canvas>

<div class="container">
<h2>&#128737; IDPS ACCESS PORTAL</h2>
<div class="sub">INTRUSION DETECTION &amp; PREVENTION SYSTEM</div>

<form method="POST">
<input type="text" name="username" placeholder="Username" required autocomplete="username">
<input type="password" name="password" placeholder="Password" required autocomplete="current-password">

<div class="btn-row">
<button class="login" type="submit" name="action" value="login">LOGIN</button>
<button class="register" type="submit" name="action" value="register">CREATE ACCOUNT</button>
</div>
</form>

<div class="msg">{{ message }}</div>

<div class="badge"><span class="dot"></span> SECURE CHANNEL ACTIVE</div>
</div>

<script>
const canvas = document.getElementById("matrix");
const ctx = canvas.getContext("2d");
canvas.height = window.innerHeight;
canvas.width = window.innerWidth;

const letters = "01";
const fontSize = 14;
let columns = canvas.width/fontSize;
let drops = [];
for(let i=0;i<columns;i++){ drops[i]=1; }

function draw(){
    ctx.fillStyle="rgba(0,0,0,0.06)";
    ctx.fillRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle="#0ff";
    ctx.font=fontSize+"px monospace";
    for(let i=0;i<drops.length;i++){
        let text=letters[Math.floor(Math.random()*letters.length)];
        ctx.fillText(text,i*fontSize,drops[i]*fontSize);
        if(drops[i]*fontSize>canvas.height && Math.random()>0.975){
            drops[i]=0;
        }
        drops[i]++;
    }
}
setInterval(draw,35);

window.addEventListener("resize", () => {
    canvas.height = window.innerHeight;
    canvas.width = window.innerWidth;
    columns = canvas.width/fontSize;
    drops = [];
    for(let i=0;i<columns;i++){ drops[i]=1; }
});
</script>

</body>
</html>
"""


# ================= PAGE CONTENT BLOCKS =================

OVERVIEW_CONTENT = """
<div class="stats">
<div class="stat-card"><div class="val" id="stat-total">0</div><div class="lbl">TOTAL EVENTS</div></div>
<div class="stat-card"><div class="val" id="stat-rate">0</div><div class="lbl">PACKETS/SEC (LATEST)</div></div>
<div class="stat-card"><div class="val" id="stat-uniq">0</div><div class="lbl">UNIQUE SOURCE IPs</div></div>
<div class="stat-card"><div class="val" id="stat-top">-</div><div class="lbl">TOP ATTACK TYPE</div></div>
<div class="stat-card"><div class="val" id="stat-unacked">0</div><div class="lbl">UNACKNOWLEDGED</div></div>
</div>

<div class="actions">
<button class="btn" onclick="updateAll()">&#128260; REFRESH NOW</button>
<a class="btn" href="/threats/chart">&#128202; OPEN THREAT CURVE</a>
<a class="btn" href="/threats/map">&#127757; OPEN ATTACK MAP</a>
<a class="btn" href="/threats/feed">&#9888; OPEN THREAT FEED</a>
</div>

<div class="card">
<h3>&#128202; Threat Curve (preview)</h3>
<p class="desc">Live packet-rate over the last 20 samples. Full controls on the Threat Curve page.</p>
<canvas id="chart" height="90"></canvas>
</div>

<div class="card">
<h3>&#9888; Most Recent Alerts</h3>
<p class="desc">Latest 5 events. Visit the Threat Feed page to search, filter, and acknowledge.</p>
<div class="feed" id="feed-preview"></div>
</div>

<script>
let ctx = document.getElementById("chart").getContext("2d");
let chart = new Chart(ctx,{
    type:"line",
    data:{ labels:[], datasets:[{ label:"Threat Activity", data:[], borderColor:"#0ff",
        backgroundColor:"rgba(0,255,255,0.08)", fill:true, tension:0.4, pointRadius:0 }] },
    options:{ scales:{ x:{ticks:{color:"#0ff"}}, y:{ticks:{color:"#0ff"}} },
        plugins:{legend:{display:false}} }
});

function sevColor(s){
    return {low:"#00E5FF", medium:"#FFD400", high:"#FF8A00", critical:"#FF3B5C"}[s] || "#0ff";
}

async function updateAll(){
    let res = await fetch("/api/metrics");
    let data = await res.json();

    chart.data.labels = data.timestamps;
    chart.data.datasets[0].data = data.packet_counts;
    chart.update();

    document.getElementById("stat-total").innerText = data.attacks.length;
    document.getElementById("stat-rate").innerText = data.packet_counts.length ? data.packet_counts[data.packet_counts.length-1] : 0;
    let uniqIps = new Set(data.attacks.map(a => a.ip));
    document.getElementById("stat-uniq").innerText = uniqIps.size;
    document.getElementById("stat-unacked").innerText = data.attacks.filter(a => !a.ack).length;
    let counts = {};
    data.attacks.forEach(a => counts[a.attack] = (counts[a.attack]||0)+1);
    let top = Object.entries(counts).sort((a,b)=>b[1]-a[1])[0];
    document.getElementById("stat-top").innerText = top ? top[0] : "-";

    let feed = document.getElementById("feed-preview");
    feed.innerHTML = "";
    data.attacks.slice().reverse().slice(0,5).forEach(a => {
        feed.innerHTML += `<div class="entry">
            <div><span class="sev" style="background:${sevColor(a.severity)}22;color:${sevColor(a.severity)}">${a.severity.toUpperCase()}</span>
            &nbsp;<b>${a.attack}</b><div class="meta">${a.ip} &middot; ${a.city}, ${a.country} &middot; ${a.time}</div></div>
        </div>`;
    });

    let dot = document.getElementById("topdot");
    let label = document.getElementById("topstatus");
    if (data.sim_paused) { dot.classList.add("paused"); label.innerText = "SIMULATOR PAUSED"; }
    else { dot.classList.remove("paused"); label.innerText = "MONITORING LIVE"; }
}

setInterval(updateAll, 5000);
updateAll();
</script>
"""

CHART_CONTENT = """
<div class="card">
<h3>&#128202; Live Threat Curve</h3>
<p class="desc">Packet-rate intensity over time, sourced from the simulated traffic engine. Auto-refreshes every 5 seconds.</p>

<div class="toggle-row">
  <label style="margin:0;">View:</label>
  <select id="rangeSelect" onchange="render()">
    <option value="10">Last 10 samples</option>
    <option value="20" selected>Last 20 samples</option>
  </select>
  <select id="typeFilter" onchange="render()">
    <option value="all">All attack types</option>
  </select>
  <button class="btn ghost" onclick="downloadCSV()">&#11015; EXPORT CSV</button>
</div>

<canvas id="chart" height="110"></canvas>
</div>

<div class="card">
<h3>Attack Type Breakdown</h3>
<p class="desc">Count of each attack type within the current sample window.</p>
<canvas id="barChart" height="100"></canvas>
</div>

<script>
let lastData = {packet_counts:[], timestamps:[], attacks:[]};

let ctx = document.getElementById("chart").getContext("2d");
let chart = new Chart(ctx,{
    type:"line",
    data:{ labels:[], datasets:[{ label:"Threat Activity", data:[], borderColor:"#0ff",
        backgroundColor:"rgba(0,255,255,0.08)", fill:true, tension:0.4 }] },
    options:{ scales:{ x:{ticks:{color:"#0ff"}}, y:{ticks:{color:"#0ff"}} },
        plugins:{legend:{labels:{color:"#0ff"}}} }
});

let barCtx = document.getElementById("barChart").getContext("2d");
let barChart = new Chart(barCtx, {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Events", data: [], backgroundColor: "#00e5ff88", borderColor:"#0ff", borderWidth:1 }] },
    options: { scales: { x:{ticks:{color:"#0ff"}}, y:{ticks:{color:"#0ff"}, beginAtZero:true} },
        plugins:{legend:{display:false}} }
});

function populateTypeFilter(attacks){
    let sel = document.getElementById("typeFilter");
    let existing = new Set(Array.from(sel.options).map(o => o.value));
    let types = [...new Set(attacks.map(a => a.attack))];
    types.forEach(t => {
        if (!existing.has(t)) {
            let opt = document.createElement("option");
            opt.value = t; opt.innerText = t;
            sel.appendChild(opt);
        }
    });
}

function render(){
    let n = parseInt(document.getElementById("rangeSelect").value);
    let labels = lastData.timestamps.slice(-n);
    let values = lastData.packet_counts.slice(-n);
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.update();

    let filterType = document.getElementById("typeFilter").value;
    let filtered = filterType === "all" ? lastData.attacks : lastData.attacks.filter(a => a.attack === filterType);
    let counts = {};
    filtered.forEach(a => counts[a.attack] = (counts[a.attack]||0)+1);
    barChart.data.labels = Object.keys(counts);
    barChart.data.datasets[0].data = Object.values(counts);
    barChart.update();
}

async function fetchData(){
    let res = await fetch("/api/metrics");
    lastData = await res.json();
    populateTypeFilter(lastData.attacks);
    render();
}

setInterval(fetchData, 5000);
fetchData();

function downloadCSV(){
    window.location.href = "/api/export.csv";
}
</script>
"""

MAP_CONTENT = """
<div class="card">
<h3>&#127757; Live Attack Map</h3>
<p class="desc">Markers show the simulated geographic origin of each event. Click a marker for details, or use the filter below.</p>

<div class="toggle-row">
  <label style="margin:0;">Severity:</label>
  <select id="sevFilter" onchange="renderMap()">
    <option value="all">All severities</option>
    <option value="low">Low</option>
    <option value="medium">Medium</option>
    <option value="high">High</option>
    <option value="critical">Critical</option>
  </select>
  <button class="btn ghost" onclick="fetchData()">&#128260; REFRESH</button>
</div>

<div id="map"></div>
</div>

<div class="card">
<h3>Top Source Locations</h3>
<table>
<thead><tr><th>City</th><th>Country</th><th>Events</th></tr></thead>
<tbody id="locTable"></tbody>
</table>
</div>

<script>
let map = L.map("map", {attributionControl:false}).setView([0, 10], 2);
L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png").addTo(map);

let markers = [];
let lastAttacks = [];

function sevColor(s){
    return {low:"#00E5FF", medium:"#FFD400", high:"#FF8A00", critical:"#FF3B5C"}[s] || "#0ff";
}

function renderMap(){
    markers.forEach(m => map.removeLayer(m));
    markers = [];
    let filter = document.getElementById("sevFilter").value;
    let filtered = filter === "all" ? lastAttacks : lastAttacks.filter(a => a.severity === filter);

    filtered.forEach(a => {
        let marker = L.circleMarker([a.lat, a.lon], {
            radius: 7, color: sevColor(a.severity), fillColor: sevColor(a.severity), fillOpacity: 0.7
        }).addTo(map).bindPopup(`<b>${a.attack}</b><br>${a.ip}<br>${a.city}, ${a.country}<br>${a.time}`);
        markers.push(marker);
    });

    let counts = {};
    filtered.forEach(a => {
        let key = a.city + "|" + a.country;
        counts[key] = (counts[key]||0) + 1;
    });
    let rows = Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8);
    let tbody = document.getElementById("locTable");
    tbody.innerHTML = "";
    rows.forEach(([key, count]) => {
        let [city, country] = key.split("|");
        tbody.innerHTML += `<tr><td>${city}</td><td>${country}</td><td>${count}</td></tr>`;
    });
}

async function fetchData(){
    let res = await fetch("/api/metrics");
    let data = await res.json();
    lastAttacks = data.attacks;
    renderMap();
}

setInterval(fetchData, 5000);
fetchData();
</script>
"""

FEED_CONTENT = """
<div class="card">
<h3>&#9888; Live Threat Feed</h3>
<p class="desc">Search, filter, and acknowledge events. Acknowledged events stay visible but fade out.</p>

<div class="toggle-row">
  <input style="margin:0;max-width:220px;" type="text" id="searchBox" placeholder="Search IP or attack type..." oninput="renderFeed()">
  <select id="sevFilter2" onchange="renderFeed()">
    <option value="all">All severities</option>
    <option value="low">Low</option>
    <option value="medium">Medium</option>
    <option value="high">High</option>
    <option value="critical">Critical</option>
  </select>
  <select id="ackFilter" onchange="renderFeed()">
    <option value="all">All statuses</option>
    <option value="unacked">Unacknowledged only</option>
    <option value="acked">Acknowledged only</option>
  </select>
  <button class="btn ghost" onclick="fetchData()">&#128260; REFRESH</button>
</div>

<div class="feed" id="feed"></div>
</div>

<script>
let lastAttacks = [];

function sevColor(s){
    return {low:"#00E5FF", medium:"#FFD400", high:"#FF8A00", critical:"#FF3B5C"}[s] || "#0ff";
}

async function ackEvent(id){
    await fetch("/api/ack/" + id, { method: "POST" });
    fetchData();
}

async function blockIP(ip){
    await fetch("/api/block/" + ip, { method: "POST" });
    fetchData();
}

function renderFeed(){
    let q = document.getElementById("searchBox").value.toLowerCase();
    let sev = document.getElementById("sevFilter2").value;
    let ackState = document.getElementById("ackFilter").value;

    let filtered = lastAttacks.filter(a => {
        if (sev !== "all" && a.severity !== sev) return false;
        if (ackState === "unacked" && a.ack) return false;
        if (ackState === "acked" && !a.ack) return false;
        if (q && !(a.ip.includes(q) || a.attack.toLowerCase().includes(q))) return false;
        return true;
    });

    let feed = document.getElementById("feed");
    feed.innerHTML = "";
    filtered.slice().reverse().forEach(a => {
        feed.innerHTML += `<div class="entry ${a.ack ? 'acked' : ''}">
            <div>
              <span class="sev" style="background:${sevColor(a.severity)}22;color:${sevColor(a.severity)}">${a.severity.toUpperCase()}</span>
              &nbsp;<b>${a.attack}</b>
              <div class="meta">IP ${a.ip} &middot; ${a.city}, ${a.country} &middot; ${a.time}</div>
            </div>
            ${a.ack ? '<span class="meta">ACKNOWLEDGED</span>' : `<div><button class="ackbtn" onclick="ackEvent(${a.id})">ACK</button> <button class="ackbtn" onclick="blockIP('${a.ip}')">BLOCK</button></div>`}
        </div>`;
    });
    if (filtered.length === 0) {
        feed.innerHTML = "<div class='entry'><span class='meta'>No events match your filters.</span></div>";
    }
}

async function fetchData(){
    let res = await fetch("/api/metrics");
    let data = await res.json();
    lastAttacks = data.attacks;
    renderFeed();
}

setInterval(fetchData, 5000);
fetchData();
</script>
"""


def settings_content(username, sim_paused, sim_speed, pw_message="", pw_ok=False):
    banner = ""
    if pw_message:
        cls = "msg-ok" if pw_ok else "msg-err"
        banner = f'<div class="msg-banner {cls}">{pw_message}</div>'
    paused_checked = "checked" if sim_paused else ""
    return f"""
<div class="card">
<h3>&#9881; Simulator Controls</h3>
<p class="desc">Pause the synthetic traffic engine or change how frequently events are generated.</p>

<div class="toggle-row">
  <label style="margin:0;"><input type="checkbox" style="width:auto;margin:0;" id="pauseToggle" {paused_checked} onchange="setPaused(this.checked)"> Pause traffic simulator</label>
</div>

<label>Event speed (higher = more frequent events)</label>
<select id="speedSelect" onchange="setSpeed(this.value)">
  <option value="0.5" {"selected" if sim_speed == 0.5 else ""}>0.5x (slow)</option>
  <option value="1" {"selected" if sim_speed == 1 else ""}>1x (normal)</option>
  <option value="2" {"selected" if sim_speed == 2 else ""}>2x (fast)</option>
  <option value="4" {"selected" if sim_speed == 4 else ""}>4x (stress test)</option>
</select>
</div>

<div class="card">
<h3>&#128100; Account</h3>
<p class="desc">Signed in as <b>{username}</b>.</p>
{banner}
<form method="POST" action="/settings/password">
<label>Current password</label>
<input type="password" name="current_password" required>
<label>New password</label>
<input type="password" name="new_password" required minlength="4">
<button class="btn" type="submit">UPDATE PASSWORD</button>
</form>
</div>

<div class="card">
<h3>&#128190; Data</h3>
<p class="desc">Export the current in-memory event log, or clear the threat feed view.</p>
<div class="actions" style="margin-bottom:0;">
<a class="btn" href="/api/export.csv">&#11015; EXPORT EVENTS CSV</a>
<button class="btn danger" onclick="clearAll()">&#128465; CLEAR ALL EVENTS</button>
</div>
</div>

<script>
async function setPaused(paused){{
    await fetch("/api/simulator", {{
        method: "POST", headers: {{"Content-Type":"application/json"}},
        body: JSON.stringify({{paused: paused}})
    }});
}}
async function setSpeed(speed){{
    await fetch("/api/simulator", {{
        method: "POST", headers: {{"Content-Type":"application/json"}},
        body: JSON.stringify({{speed: parseFloat(speed)}})
    }});
}}
async function clearAll(){{
    if (!confirm("Clear all recorded events? This cannot be undone.")) return;
    await fetch("/api/clear", {{ method: "POST" }});
    alert("Events cleared.");
}}
</script>
"""


# ================= AUTH ROUTES =================

@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    ok = False

    if request.method == "POST":
        action = request.form.get("action")
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "").strip()

        if action == "register":
            if not username or not password:
                message = "Enter username and password"
            else:
                cursor.execute("SELECT * FROM users WHERE username=?", (username,))
                existing = cursor.fetchone()
                if existing:
                    message = "Username already exists"
                else:
                    hashed = generate_password_hash(password)
                    cursor.execute(
                        "INSERT INTO users(username,password,created_at) VALUES(?,?,?)",
                        (username, hashed, time.strftime("%Y-%m-%d %H:%M:%S"))
                    )
                    conn.commit()
                    message = "Account created successfully. You can log in now."
                    ok = True

        elif action == "login":
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user[2], password):
                session["user"] = username
                return redirect("/dashboard")
            else:
                message = "Invalid login credentials"

    return render_template_string(LOGIN_PAGE, message=message, ok=ok)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


def require_login():
    return "user" in session


# ================= PAGE ROUTES =================

@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect("/")
    html = page_shell("overview", session["user"], "Overview", "MONITORING LIVE", OVERVIEW_CONTENT)
    return html


@app.route("/threats/chart")
def threats_chart():
    if not require_login():
        return redirect("/")
    html = page_shell("chart", session["user"], "Threat Curve", "MONITORING LIVE", CHART_CONTENT)
    return html


@app.route("/threats/map")
def threats_map():
    if not require_login():
        return redirect("/")
    html = page_shell("map", session["user"], "Attack Map", "MONITORING LIVE", MAP_CONTENT)
    return html


@app.route("/threats/feed")
def threats_feed():
    if not require_login():
        return redirect("/")
    html = page_shell("feed", session["user"], "Threat Feed", "MONITORING LIVE", FEED_CONTENT)
    return html


@app.route("/settings", methods=["GET"])
def settings():
    if not require_login():
        return redirect("/")
    with sim_lock:
        paused = sim_state["paused"]
        speed = sim_state["speed"]
    content = settings_content(session["user"], paused, speed)
    html = page_shell("settings", session["user"], "Settings", "MONITORING LIVE", content)
    return html


@app.route("/settings/password", methods=["POST"])
def settings_password():
    if not require_login():
        return redirect("/")
    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""

    cursor.execute("SELECT * FROM users WHERE username=?", (session["user"],))
    user = cursor.fetchone()

    with sim_lock:
        paused = sim_state["paused"]
        speed = sim_state["speed"]

    if not user or not check_password_hash(user[2], current_password):
        content = settings_content(session["user"], paused, speed, "Current password is incorrect.", False)
    elif len(new_password) < 4:
        content = settings_content(session["user"], paused, speed, "New password must be at least 4 characters.", False)
    else:
        hashed = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed, session["user"]))
        conn.commit()
        content = settings_content(session["user"], paused, speed, "Password updated successfully.", True)

    return page_shell("settings", session["user"], "Settings", "MONITORING LIVE", content)


# ================= JSON API =================

@app.route("/api/metrics")
def api_metrics():
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401
    with data_lock:
        attacks_copy = list(attacks)
    with sim_lock:
        paused = sim_state["paused"]
    return jsonify({
        "packet_counts": list(packet_counts),
        "timestamps": list(timestamps),
        "attacks": attacks_copy,
        "blocked_ips": list(blocked_ips),
        "manual_blocked_ips": list(manual_blocked_ips),
        "sim_paused": paused,
    })


@app.route("/api/ack/<int:event_id>", methods=["POST"])
def api_ack(event_id):
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401
    with data_lock:
        for a in attacks:
            if a["id"] == event_id:
                a["ack"] = True
                break
    return jsonify({"ok": True})


@app.route("/api/simulator", methods=["POST"])
def api_simulator():
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    with sim_lock:
        if "paused" in payload:
            sim_state["paused"] = bool(payload["paused"])
        if "speed" in payload:
            try:
                sim_state["speed"] = max(0.1, float(payload["speed"]))
            except (TypeError, ValueError):
                pass
    return jsonify({"ok": True, "state": sim_state})


@app.route("/api/clear", methods=["POST"])
def api_clear():
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401
    with data_lock:
        attacks.clear()
        timestamps.clear()
        packet_counts.clear()
    return jsonify({"ok": True})


@app.route("/api/export.csv")
def api_export_csv():
    if not require_login():
        return redirect("/")
    with data_lock:
        attacks_copy = list(attacks)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "time", "ip", "attack", "severity", "city", "country", "lat", "lon", "acknowledged"])
    for a in attacks_copy:
        writer.writerow([a["id"], a["time"], a["ip"], a["attack"], a["severity"],
                          a["city"], a["country"], a["lat"], a["lon"], a["ack"]])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=idps_events.csv"},
    )


# ================= RUN =================


@app.route("/api/block/<ip>", methods=["POST"])
def block_ip(ip):
    blocked_ips.add(ip)
    manual_blocked_ips.add(ip)
    return jsonify({"success": True})

@app.route("/api/unblock/<ip>", methods=["POST"])
def unblock_ip(ip):
    blocked_ips.discard(ip)
    return jsonify({"success": True})

@app.route("/blocked")
def blocked_page():
    if "user" not in session:
        return redirect("/")

    all_blocked = sorted(blocked_ips | manual_blocked_ips)
    rows = "".join(
        f"<tr><td>{ip}</td><td><button onclick=\"unblockIP('{ip}')\">UNBLOCK</button></td></tr>"
        for ip in all_blocked
    )

    content = f"""
    <div class='card'>
    <h2>Blocked Attackers</h2>
    <table style='width:100%'>
    <tr><th>IP</th><th>Action</th></tr>
    {rows}
    </table>
    </div>
    <script>
    async function unblockIP(ip){{
      await fetch('/api/unblock/' + ip, {{method:'POST'}});
      location.reload();
    }}
    </script>
    """
    return page_shell("blocked", session["user"], "Blocked Attackers", "Prevention Active", content)


if __name__ == "__main__":
    threading.Thread(target=start_traffic_simulator, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=True)