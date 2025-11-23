import React, { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  Zap,
  Search,
  Lock,
  Clock,
  CheckCircle2,
  XCircle,
  BarChart3,
  Activity,
  Server
} from "lucide-react";

function ResponseBox({ title, status, body, error }) {
  return (
    <div className="mt-4 rounded-xl border border-neutral-800 bg-neutral-900/60 p-4 text-sm">
      <div className="flex items-center justify-between mb-2">
        <span className="font-medium text-neutral-200">{title}</span>
        {typeof status === "number" && (
          <span
            className={`px-2 py-0.5 rounded-full text-xs ${
              status < 300
                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/40"
                : status < 500
                ? "bg-amber-500/10 text-amber-400 border border-amber-500/40"
                : "bg-rose-500/10 text-rose-400 border border-rose-500/40"
            }`}
          >
            HTTP {status}
          </span>
        )}
      </div>
      {error && (
        <p className="text-rose-400 mb-2 flex items-center gap-1">
          <XCircle className="w-4 h-4" />
          {error}
        </p>
      )}
      {body ? (
        <pre className="mt-1 max-h-64 overflow-auto text-xs text-neutral-300 bg-black/40 rounded-lg p-3 border border-neutral-800/80">
          {body}
        </pre>
      ) : !error ? (
        <p className="text-neutral-500 text-xs">No response yet.</p>
      ) : null}
    </div>
  );
}

export default function WebTrustAnalyzer() {
  // LOGIN
  const [loginUser, setLoginUser] = useState("admin");
  const [loginPass, setLoginPass] = useState("password");
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginStatus, setLoginStatus] = useState(null);
  const [loginBody, setLoginBody] = useState("");
  const [loginError, setLoginError] = useState("");

  // SEARCH
  const [searchQuery, setSearchQuery] = useState("");
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchStatus, setSearchStatus] = useState(null);
  const [searchBody, setSearchBody] = useState("");
  const [searchError, setSearchError] = useState("");

  // RATE LIMIT
  const [burstRunning, setBurstRunning] = useState(false);
  const [burstCount, setBurstCount] = useState(20);
  const [burstLog, setBurstLog] = useState([]);

  // STATS
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);

  const API_BASE = "http://localhost:8080";

  // Fetch stats and logs
  useEffect(() => {
    fetchStats();
    fetchLogs();
    const interval = setInterval(() => {
      fetchStats();
      fetchLogs();
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/firewall/stats`);
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error("Failed to fetch stats:", err);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/firewall/logs`);
      if (res.ok) {
        const data = await res.json();
        setLogs(data);
      }
    } catch (err) {
      console.error("Failed to fetch logs:", err);
    }
  };

  const safeSetJson = (set, obj) => {
    try {
      set(JSON.stringify(obj, null, 2));
    } catch {
      set(String(obj));
    }
  };

  const handleLogin = async (attack = false) => {
    setLoginLoading(true);
    setLoginError("");
    setLoginBody("");
    setLoginStatus(null);

    const payload = attack
      ? { username: "admin' OR 1=1--", password: "anything" }
      : { username: loginUser, password: loginPass };

    try {
      const res = await fetch(`${API_BASE}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      setLoginStatus(res.status);
      const text = await res.text();
      
      try {
        const json = JSON.parse(text);
        safeSetJson(setLoginBody, json);
      } catch {
        setLoginBody(text || "(empty response)");
      }
    } catch (err) {
      setLoginError("Network error or firewall blocked before response.");
    } finally {
      setLoginLoading(false);
    }
  };

  const handleSearch = async (mode) => {
    setSearchLoading(true);
    setSearchError("");
    setSearchBody("");
    setSearchStatus(null);

    let q = searchQuery || "hello";

    if (mode === "sqli") {
      q = "' OR 1=1--";
    } else if (mode === "xss") {
      q = '<script>alert(1)</script>';
    }

    try {
      const res = await fetch(`${API_BASE}/api/search?q=${encodeURIComponent(q)}`);
      setSearchStatus(res.status);
      const text = await res.text();
      try {
        const json = JSON.parse(text);
        safeSetJson(setSearchBody, json);
      } catch {
        setSearchBody(text || "(empty response)");
      }
    } catch (err) {
      setSearchError("Network error or firewall blocked before response.");
    } finally {
      setSearchLoading(false);
    }
  };

  const runBurst = async () => {
    setBurstRunning(true);
    setBurstLog([]);
    const total = Math.max(1, burstCount);
    const newLog = [];

    for (let i = 1; i <= total; i++) {
      try {
        const res = await fetch(`${API_BASE}/api/search?q=ratelimit-demo`);
        newLog.push(`Request #${i}: HTTP ${res.status}`);
      } catch (e) {
        newLog.push(`Request #${i}: FAILED (blocked)`);
      }
      await new Promise((r) => setTimeout(r, 50));
      setBurstLog([...newLog]);
    }
    setBurstRunning(false);
  };

  const featureCards = [
    {
      icon: <Zap className="w-5 h-5 text-amber-400" />,
      title: "Rate Limiting",
      desc: "Intelligent rate limiting with IP-based tracking and automatic blocking.",
    },
    {
      icon: <Search className="w-5 h-5 text-sky-400" />,
      title: "SQL Injection Protection",
      desc: "Advanced pattern matching for SQL injection attempts with real-time blocking.",
    },
    {
      icon: <AlertTriangle className="w-5 h-5 text-rose-400" />,
      title: "XSS Protection",
      desc: "Comprehensive XSS detection with script tag and event handler blocking.",
    },
    {
      icon: <Activity className="w-5 h-5 text-emerald-400" />,
      title: "Real-time Monitoring",
      desc: "Live threat monitoring with detailed analytics and logging.",
    },
  ];

  const getThreatColor = (type) => {
    switch (type) {
      case 'SQL_INJECTION': return 'text-rose-400';
      case 'XSS': return 'text-amber-400';
      case 'RATE_LIMIT_EXCEEDED': return 'text-purple-400';
      case 'PATH_TRAVERSAL': return 'text-orange-400';
      default: return 'text-neutral-400';
    }
  };

  return (
    <div className="min-h-screen bg-black text-neutral-100 flex flex-col">
      {/* Header */}
      <header className="border-b border-neutral-800 bg-neutral-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-emerald-500 to-sky-500 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-emerald-400 to-sky-400 bg-clip-text text-transparent">
                Web Trust Analyzer
              </h1>
              <p className="text-xs text-neutral-400">
                Advanced Web Application Firewall with Real-time Threat Detection
              </p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {stats && (
              <div className="flex items-center gap-4 text-xs">
                <div className="text-emerald-400">
                  <CheckCircle2 className="w-4 h-4 inline mr-1" />
                  Allowed: {stats.total_requests - stats.blocked_requests}
                </div>
                <div className="text-rose-400">
                  <XCircle className="w-4 h-4 inline mr-1" />
                  Blocked: {stats.blocked_requests}
                </div>
                <div className="text-amber-400">
                  <Activity className="w-4 h-4 inline mr-1" />
                  Threats: {stats.total_threats}
                </div>
              </div>
            )}
            <div className="flex items-center gap-2 text-xs text-neutral-400">
              <Server className="w-4 h-4" />
              <span>Go Firewall Active</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 py-8 space-y-8">
        {/* Stats Dashboard */}
        {stats && (
          <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/60 p-4">
              <div className="text-2xl font-bold text-emerald-400">{stats.total_requests}</div>
              <div className="text-xs text-neutral-400">Total Requests</div>
            </div>
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/60 p-4">
              <div className="text-2xl font-bold text-rose-400">{stats.blocked_requests}</div>
              <div className="text-xs text-neutral-400">Blocked Requests</div>
            </div>
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/60 p-4">
              <div className="text-2xl font-bold text-amber-400">{stats.total_threats}</div>
              <div className="text-xs text-neutral-400">Threats Detected</div>
            </div>
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/60 p-4">
              <div className="text-2xl font-bold text-purple-400">{stats.blocked_ips}</div>
              <div className="text-xs text-neutral-400">Blocked IPs</div>
            </div>
          </section>
        )}

        {/* Feature Cards */}
        <section className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
          {featureCards.map((f) => (
            <div
              key={f.title}
              className="flex gap-3 rounded-2xl border border-neutral-800 bg-neutral-900/40 p-4 hover:bg-neutral-900/60 transition-colors"
            >
              <div className="mt-0.5">{f.icon}</div>
              <div>
                <h3 className="text-sm font-semibold mb-1">{f.title}</h3>
                <p className="text-xs text-neutral-400 leading-relaxed">{f.desc}</p>
              </div>
            </div>
          ))}
        </section>

        <section className="grid gap-6 lg:grid-cols-2">
          {/* Left Column - Testing Tools */}
          <div className="space-y-6">
            {/* Login Tester */}
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/40 p-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-8 w-8 rounded-xl bg-neutral-800 flex items-center justify-center border border-neutral-700">
                  <Lock className="w-4 h-4 text-emerald-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Login Firewall Tester</h3>
                  <p className="text-xs text-neutral-400">
                    Test SQL injection protection with login endpoints
                  </p>
                </div>
              </div>

              <div className="space-y-3 text-sm">
                <div className="flex gap-3">
                  <div className="flex-1">
                    <label className="block text-xs text-neutral-400 mb-1">
                      Username
                    </label>
                    <input
                      className="w-full rounded-lg bg-neutral-800 border border-neutral-700 px-3 py-2 text-sm outline-none focus:border-emerald-500"
                      value={loginUser}
                      onChange={(e) => setLoginUser(e.target.value)}
                    />
                  </div>
                  <div className="flex-1">
                    <label className="block text-xs text-neutral-400 mb-1">
                      Password
                    </label>
                    <input
                      type="password"
                      className="w-full rounded-lg bg-neutral-800 border border-neutral-700 px-3 py-2 text-sm outline-none focus:border-emerald-500"
                      value={loginPass}
                      onChange={(e) => setLoginPass(e.target.value)}
                    />
                  </div>
                </div>

                <div className="flex gap-2">
                  <button
                    onClick={() => handleLogin(false)}
                    disabled={loginLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-sm font-medium text-black disabled:opacity-50 transition-colors"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Normal Login
                  </button>
                  <button
                    onClick={() => handleLogin(true)}
                    disabled={loginLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/60 px-4 py-2 text-sm font-medium text-rose-100 disabled:opacity-50 transition-colors"
                  >
                    <AlertTriangle className="w-4 h-4" />
                    SQL Injection Test
                  </button>
                </div>

                <ResponseBox
                  title="Login API Response"
                  status={loginStatus}
                  body={loginBody}
                  error={loginError}
                />
              </div>
            </div>

            {/* Search Tester */}
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/40 p-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-8 w-8 rounded-xl bg-neutral-800 flex items-center justify-center border border-neutral-700">
                  <Search className="w-4 h-4 text-sky-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Search & Payload Tester</h3>
                  <p className="text-xs text-neutral-400">
                    Test various attack payloads on search endpoints
                  </p>
                </div>
              </div>

              <div className="space-y-3 text-sm">
                <div>
                  <label className="block text-xs text-neutral-400 mb-1">
                    Custom Search Query
                  </label>
                  <input
                    className="w-full rounded-lg bg-neutral-800 border border-neutral-700 px-3 py-2 text-sm outline-none focus:border-sky-500"
                    placeholder="Enter normal search text..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => handleSearch("normal")}
                    disabled={searchLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-sky-500 hover:bg-sky-400 px-4 py-2 text-sm font-medium text-black disabled:opacity-50 transition-colors"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    Normal Search
                  </button>
                  <button
                    onClick={() => handleSearch("sqli")}
                    disabled={searchLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/60 px-4 py-2 text-sm font-medium text-rose-100 disabled:opacity-50 transition-colors"
                  >
                    <AlertTriangle className="w-4 h-4" />
                    SQL Injection
                  </button>
                  <button
                    onClick={() => handleSearch("xss")}
                    disabled={searchLoading}
                    className="inline-flex items-center gap-2 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/60 px-4 py-2 text-sm font-medium text-amber-100 disabled:opacity-50 transition-colors"
                  >
                    <AlertTriangle className="w-4 h-4" />
                    XSS Payload
                  </button>
                </div>

                <ResponseBox
                  title="Search API Response"
                  status={searchStatus}
                  body={searchBody}
                  error={searchError}
                />
              </div>
            </div>
          </div>

          {/* Right Column - Monitoring */}
          <div className="space-y-6">
            {/* Rate Limit Tester */}
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/40 p-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-8 w-8 rounded-xl bg-neutral-800 flex items-center justify-center border border-neutral-700">
                  <Zap className="w-4 h-4 text-amber-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Rate Limit Testing</h3>
                  <p className="text-xs text-neutral-400">
                    Test the firewall's rate limiting capabilities
                  </p>
                </div>
              </div>

              <div className="space-y-3 text-sm">
                <div className="flex items-center gap-3">
                  <label className="text-xs text-neutral-400 whitespace-nowrap">
                    Requests to send:
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={200}
                    value={burstCount}
                    onChange={(e) =>
                      setBurstCount(parseInt(e.target.value || "1", 10))
                    }
                    className="w-20 rounded-lg bg-neutral-800 border border-neutral-700 px-3 py-2 text-sm outline-none focus:border-amber-500"
                  />
                  <button
                    onClick={runBurst}
                    disabled={burstRunning}
                    className="inline-flex items-center gap-2 rounded-lg bg-amber-500 hover:bg-amber-400 px-4 py-2 text-sm font-medium text-black disabled:opacity-50 transition-colors"
                  >
                    <Zap className="w-4 h-4" />
                    {burstRunning ? "Running..." : "Run Burst Test"}
                  </button>
                </div>

                <div className="mt-3 max-h-40 overflow-auto rounded-lg bg-black/40 border border-neutral-800 p-3 text-xs font-mono text-neutral-300 space-y-1">
                  {burstLog.length === 0 ? (
                    <p className="text-neutral-500">
                      Burst test logs will appear here...
                    </p>
                  ) : (
                    burstLog.map((line, i) => (
                      <div key={i} className="py-1 border-b border-neutral-800 last:border-b-0">
                        {line}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Threat Logs */}
            <div className="rounded-2xl border border-neutral-800 bg-neutral-900/40 p-6">
              <div className="flex items-center gap-2 mb-4">
                <div className="h-8 w-8 rounded-xl bg-neutral-800 flex items-center justify-center border border-neutral-700">
                  <BarChart3 className="w-4 h-4 text-purple-400" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold">Real-time Threat Logs</h3>
                  <p className="text-xs text-neutral-400">
                    Live monitoring of detected threats and security events
                  </p>
                </div>
              </div>

              <div className="max-h-96 overflow-auto rounded-lg bg-black/40 border border-neutral-800">
                {logs.length === 0 ? (
                  <div className="p-4 text-center text-neutral-500 text-sm">
                    No threat logs yet. Start testing to see detected threats.
                  </div>
                ) : (
                  <div className="divide-y divide-neutral-800">
                    {logs.slice(0, 20).map((log) => (
                      <div key={log.id} className="p-3 hover:bg-neutral-800/20 transition-colors">
                        <div className="flex items-center justify-between mb-1">
                          <span className={`text-xs font-medium ${getThreatColor(log.type)}`}>
                            {log.type}
                          </span>
                          <span className="text-xs text-neutral-500">
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <div className="text-xs text-neutral-400 mb-1">
                          IP: {log.ip} • {log.method} {log.endpoint}
                        </div>
                        {log.details && (
                          <div className="text-xs text-neutral-500 truncate">
                            {log.details}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-neutral-800 bg-neutral-950/80 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between text-xs text-neutral-500">
            <div>
              <span className="font-medium text-neutral-400">Web Trust Analyzer</span> • 
              Advanced Web Application Firewall with Real-time Protection
            </div>
            <div>
              Powered by Go • React • Real-time Analytics
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}