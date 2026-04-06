//! Sentinel GUI — standalone web dashboard for PlausiDen Sentinel.
//!
//! Serves a modern dark-themed dashboard at http://localhost:9001
//! with real-time system security status, threat feed, and scan controls.

use axum::{
    extract::Json,
    response::Html,
    routing::{get, post},
    Router,
};
use chrono::Utc;
use plausiden_sentinel::detection::credential_theft::CredentialTheftDetector;
use plausiden_sentinel::detection::forensic_detector::ForensicDetector;
use plausiden_sentinel::detection::kernel_monitor::KernelMonitor;
use plausiden_sentinel::detection::privilege_escalation::PrivEscDetector;
use plausiden_sentinel::detection::process_injection::InjectionDetector;
use plausiden_sentinel::detection::rootkit::RootkitDetector;
use plausiden_sentinel::detection::threat::{ThreatEvent, ThreatLevel};
use plausiden_sentinel::network::connection_monitor::ConnectionMonitor;
use serde::Serialize;
use std::sync::{Arc, Mutex};

#[derive(Clone, Serialize)]
struct ScanResult {
    timestamp: String,
    process_count: usize,
    threats: Vec<ThreatInfo>,
    status: String,
    scan_duration_ms: u64,
    kernel_version: String,
    uptime: String,
    tcp_established: usize,
    tcp_listening: usize,
    tcp_external: usize,
    kernel_hardened: bool,
    kernel_recommendations: usize,
}

#[derive(Clone, Serialize)]
struct ThreatInfo {
    level: String,
    description: String,
    confidence: f64,
    category: String,
}

impl From<&ThreatEvent> for ThreatInfo {
    fn from(e: &ThreatEvent) -> Self {
        Self {
            level: format!("{:?}", e.level),
            description: e.description.clone(),
            confidence: e.confidence,
            category: format!("{:?}", e.category),
        }
    }
}

type SharedState = Arc<Mutex<Option<ScanResult>>>;

#[tokio::main]
async fn main() {
    let state: SharedState = Arc::new(Mutex::new(None));

    // Run initial scan.
    let initial = run_scan();
    *state.lock().unwrap() = Some(initial);

    let app = Router::new()
        .route("/", get(dashboard_page))
        .route("/api/scan", post({
            let state = state.clone();
            move || trigger_scan(state)
        }))
        .route("/api/status", get({
            let state = state.clone();
            move || get_status(state)
        }));

    println!("\n\x1b[1;36m[SENTINEL GUI]\x1b[0m Dashboard running at \x1b[1mhttp://localhost:9001\x1b[0m");
    println!("  Open in your browser to view system security status.\n");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:9001").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn dashboard_page() -> Html<String> {
    Html(render_dashboard())
}

async fn trigger_scan(state: SharedState) -> Json<ScanResult> {
    let result = run_scan();
    *state.lock().unwrap() = Some(result.clone());
    Json(result)
}

async fn get_status(state: SharedState) -> Json<Option<ScanResult>> {
    Json(state.lock().unwrap().clone())
}

fn run_scan() -> ScanResult {
    let start = std::time::Instant::now();
    let mut threats: Vec<ThreatEvent> = Vec::new();

    // Get running processes.
    let procs = get_running_processes();

    // 1. Injection detection.
    let inj = InjectionDetector::new();
    threats.extend(inj.check_ld_preload_injection());

    // 2. Forensic tool detection.
    let mut forensic = ForensicDetector::new();
    let proc_refs: Vec<&str> = procs.iter().map(|s| s.as_str()).collect();
    threats.extend(forensic.scan_processes(&proc_refs));

    // 3. Credential theft.
    let cred = CredentialTheftDetector::new();
    for proc_name in &procs {
        if let Some(e) = cred.check_process(proc_name) {
            threats.push(e);
        }
    }

    // 4. Rootkit indicators.
    let rootkit = RootkitDetector::new();
    let preload = std::env::var("LD_PRELOAD").unwrap_or_default();
    let preload_entries: Vec<&str> = preload.split(':').filter(|s| !s.is_empty()).collect();
    threats.extend(rootkit.check_preload_rootkit(&preload_entries));

    // 5. SUID checks.
    let priv_det = PrivEscDetector::new();
    for dir in &["/tmp", "/dev/shm", "/var/tmp"] {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(meta) = entry.metadata() {
                        if meta.mode() & 0o4000 != 0 {
                            let path = entry.path().to_string_lossy().to_string();
                            if let Some(e) = priv_det.check_suid_abuse(&path, "root") {
                                threats.push(e);
                            }
                        }
                    }
                }
            }
        }
    }

    let elapsed = start.elapsed();
    let critical = threats.iter().filter(|t| matches!(t.level, ThreatLevel::Critical)).count();
    let high = threats.iter().filter(|t| matches!(t.level, ThreatLevel::High)).count();

    let status = if critical > 0 { "CRITICAL" }
    else if high > 0 { "WARNING" }
    else if !threats.is_empty() { "ALERT" }
    else { "CLEAN" };

    // Network connection stats.
    let established = ConnectionMonitor::established_connections().len();
    let listening = ConnectionMonitor::listening_ports().len();
    let external = ConnectionMonitor::external_connections().len();

    // Kernel security state.
    let kernel_state = KernelMonitor::read_state();
    let kernel_recs = KernelMonitor::recommendations(&kernel_state);
    let kernel_hardened = KernelMonitor::is_hardened(&kernel_state);

    ScanResult {
        timestamp: Utc::now().to_rfc3339(),
        process_count: procs.len(),
        threats: threats.iter().map(ThreatInfo::from).collect(),
        status: status.into(),
        scan_duration_ms: elapsed.as_millis() as u64,
        kernel_version: get_kernel_version(),
        uptime: get_uptime(),
        tcp_established: established,
        tcp_listening: listening,
        tcp_external: external,
        kernel_hardened,
        kernel_recommendations: kernel_recs.len(),
    }
}

fn get_running_processes() -> Vec<String> {
    let mut procs = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                    procs.push(comm.trim().to_string());
                }
            }
        }
    }
    procs
}

fn get_kernel_version() -> String {
    std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .split_whitespace()
        .nth(2)
        .unwrap_or("unknown")
        .to_string()
}

fn get_uptime() -> String {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(|s| s.to_string()))
        .and_then(|s| s.parse::<f64>().ok())
        .map(|secs| {
            let hours = (secs / 3600.0) as u64;
            let mins = ((secs % 3600.0) / 60.0) as u64;
            format!("{hours}h {mins}m")
        })
        .unwrap_or_else(|| "unknown".into())
}

fn render_dashboard() -> String {
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel — Security Dashboard</title>
<style>
:root {{ --bg: #0a0a1a; --surface: #12122a; --border: #1e1e3a; --accent: #50fa7b; --danger: #ff5555; --warning: #f1fa8c; --text: #e0e0e0; --muted: #888; --font: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: var(--font); background: var(--bg); color: var(--text); min-height: 100vh; }}
.header {{ background: linear-gradient(135deg, #1a1a3e 0%, #0a0a1a 100%); border-bottom: 1px solid var(--border); padding: 1.5rem 2rem; display: flex; align-items: center; justify-content: space-between; }}
.header h1 {{ font-size: 1.5rem; color: var(--accent); font-weight: 700; }}
.header .subtitle {{ color: var(--muted); font-size: 0.85rem; }}
.scan-btn {{ background: var(--accent); color: #000; border: none; padding: 0.6rem 1.5rem; border-radius: 6px; font-family: var(--font); font-weight: 600; cursor: pointer; font-size: 0.9rem; }}
.scan-btn:hover {{ opacity: 0.9; }}
.scan-btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; padding: 1.5rem 2rem; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }}
.card .label {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }}
.card .value {{ font-size: 1.8rem; font-weight: 700; }}
.card .value.clean {{ color: var(--accent); }}
.card .value.warning {{ color: var(--warning); }}
.card .value.critical {{ color: var(--danger); }}
.threats {{ padding: 0 2rem 2rem; }}
.threats h2 {{ font-size: 1.1rem; margin-bottom: 1rem; color: var(--muted); }}
.threat-list {{ display: flex; flex-direction: column; gap: 0.5rem; }}
.threat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem 1rem; display: flex; align-items: center; gap: 1rem; }}
.threat .badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }}
.badge.Critical {{ background: var(--danger); color: #000; }}
.badge.High {{ background: #ff7944; color: #000; }}
.badge.Medium {{ background: var(--warning); color: #000; }}
.badge.Low {{ background: #6272a4; color: #fff; }}
.badge.Info {{ background: #444; color: #ccc; }}
.threat .desc {{ font-size: 0.85rem; flex: 1; }}
.threat .conf {{ color: var(--muted); font-size: 0.75rem; }}
.empty {{ color: var(--muted); font-style: italic; padding: 2rem; text-align: center; }}
#last-scan {{ color: var(--muted); font-size: 0.8rem; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <h1>SENTINEL</h1>
    <div class="subtitle">AI-Powered IDS/IPS — PlausiDen Protection Suite</div>
  </div>
  <div style="display:flex;align-items:center;gap:1rem;">
    <span id="last-scan">Loading...</span>
    <button class="scan-btn" onclick="runScan()">Run Scan</button>
  </div>
</div>

<div class="grid" id="stats">
  <div class="card"><div class="label">Status</div><div class="value" id="status">—</div></div>
  <div class="card"><div class="label">Processes</div><div class="value" id="procs">—</div></div>
  <div class="card"><div class="label">Threats</div><div class="value" id="threat-count">—</div></div>
  <div class="card"><div class="label">Scan Time</div><div class="value" id="scan-time">—</div></div>
  <div class="card"><div class="label">Kernel</div><div class="value" id="kernel" style="font-size:0.9rem">—</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value" id="uptime">—</div></div>
  <div class="card"><div class="label">TCP Established</div><div class="value" id="tcp-est">—</div></div>
  <div class="card"><div class="label">Listening Ports</div><div class="value" id="tcp-listen">—</div></div>
  <div class="card"><div class="label">External Connections</div><div class="value" id="tcp-ext">—</div></div>
  <div class="card"><div class="label">Kernel</div><div class="value" id="kernel-state">—</div></div>
  <div class="card"><div class="label">Hardening Recs</div><div class="value" id="kernel-recs">—</div></div>
</div>

<div class="threats">
  <h2>Threat Feed</h2>
  <div class="threat-list" id="threat-list">
    <div class="empty">No scan data yet. Click "Run Scan" to start.</div>
  </div>
</div>

<script>
async function loadStatus() {{
  try {{
    const res = await fetch('/api/status');
    const data = await res.json();
    if (data) updateUI(data);
  }} catch(e) {{ console.error(e); }}
}}

async function runScan() {{
  const btn = document.querySelector('.scan-btn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  try {{
    const res = await fetch('/api/scan', {{ method: 'POST' }});
    const data = await res.json();
    updateUI(data);
  }} catch(e) {{ console.error(e); }}
  btn.disabled = false;
  btn.textContent = 'Run Scan';
}}

function updateUI(data) {{
  const s = document.getElementById('status');
  s.textContent = data.status;
  s.className = 'value ' + data.status.toLowerCase();

  document.getElementById('procs').textContent = data.process_count;
  document.getElementById('threat-count').textContent = data.threats.length;
  document.getElementById('scan-time').textContent = data.scan_duration_ms + 'ms';
  document.getElementById('kernel').textContent = data.kernel_version;
  document.getElementById('uptime').textContent = data.uptime;
  document.getElementById('last-scan').textContent = 'Last: ' + new Date(data.timestamp).toLocaleTimeString();
  document.getElementById('tcp-est').textContent = data.tcp_established;
  document.getElementById('tcp-listen').textContent = data.tcp_listening;
  const extEl = document.getElementById('tcp-ext');
  extEl.textContent = data.tcp_external;
  extEl.className = data.tcp_external > 50 ? 'value warning' : 'value';
  const kernelEl = document.getElementById('kernel-state');
  kernelEl.textContent = data.kernel_hardened ? 'HARDENED' : 'NEEDS WORK';
  kernelEl.className = data.kernel_hardened ? 'value clean' : 'value warning';
  kernelEl.style.fontSize = '0.9rem';
  document.getElementById('kernel-recs').textContent = data.kernel_recommendations;

  const list = document.getElementById('threat-list');
  if (data.threats.length === 0) {{
    list.innerHTML = '<div class="empty" style="color:var(--accent)">System is clean. No threats detected.</div>';
  }} else {{
    list.innerHTML = data.threats.map(t =>
      `<div class="threat">
        <span class="badge ${{t.level}}">${{t.level}}</span>
        <span class="desc">${{t.description}}</span>
        <span class="conf">${{(t.confidence*100).toFixed(0)}}%</span>
      </div>`
    ).join('');
  }}
}}

loadStatus();
setInterval(loadStatus, 30000);
</script>
</body>
</html>"#)
}
