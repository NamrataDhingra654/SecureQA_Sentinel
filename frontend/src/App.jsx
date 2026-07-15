import { useState, useEffect, useRef } from "react"
import { Shield, Zap, AlertTriangle, Info, CheckCircle, Clock, TrendingUp, AlertCircle, ChevronDown, History, Search, X, FileText, RefreshCw, ShieldCheck, ShieldAlert, Sparkles, MessageCircle, Send, Download, GitCompare, ArrowRight, Minus } from "lucide-react"
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts"

const API_BASE = import.meta.env.VITE_API_URL
  ? `${import.meta.env.VITE_API_URL}/api`
  : "http://127.0.0.1:5000/api"
const POLL_INTERVAL_MS = 1500

const SEVERITY_FILTERS = ["All", "High", "Medium", "Low", "Info"]
const PAGE_SIZE = 50

// ── Real-progress helpers (replace the old fake-interval simulation) ────────
function phaseLabel(phase) {
  switch (phase) {
    case "spider":      return "Spider crawling…"
    case "active_scan": return "Active scanning…"
    case "unknown":     return "Processing…"
    default:            return ""
  }
}

// Maps ZAP's real per-phase percentage onto the overall 0-100 bar:
// spider owns 2-48%, active scan owns 48-95%. The last 5% (95-100) is
// reserved for fetching findings + loading the detail view after "complete".
function computeProgress(phase, percent) {
  const pct = typeof percent === "number" ? percent : 0
  if (phase === "spider")      return Math.min(48, 2 + pct * 0.46)
  if (phase === "active_scan") return Math.min(95, 48 + pct * 0.47)
  return 50 // "unknown" phase — transient read failure on the backend, hold steady
}
function CustomTooltip({ active, payload }) {
  if (active && payload?.length) {
    return (
      <div style={{ background: "#13131a", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: "8px 12px" }}>
        <p style={{ color: payload[0].payload.color || "#fff", fontSize: 13, fontWeight: 600 }}>{payload[0].name}</p>
        <p style={{ color: "rgba(255,255,255,0.5)", fontSize: 12 }}>{payload[0].value} findings</p>
      </div>
    )
  }
  return null
}

export default function App() {
  const [url, setUrl]             = useState("")
  const [scanning, setScanning]   = useState(false)
  const [progress, setProgress]   = useState(0)
  const [phase, setPhase]         = useState("")
  const [scan, setScan]           = useState(null)
  const [error, setError]         = useState(null)

  // History
  const [pastScans, setPastScans]       = useState([])
  const [dropdownOpen, setDropdownOpen] = useState(false)
  const [loadingPast, setLoadingPast]   = useState(false)
  const [loadingList, setLoadingList]   = useState(true)

  // Findings filter + pagination
  const [filterSeverity, setFilterSeverity] = useState("All")
  const [searchQuery, setSearchQuery]       = useState("")
  const [page, setPage]                     = useState(1)

  // AI report
  const [report, setReport]           = useState(null)   // { report_text, generated_at, cached, backend }
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError, setReportError] = useState(null)
  const [backendChoice, setBackendChoice] = useState("ollama")  // "ollama" (local) or "groq" (cloud)

  // Chatbot Q&A — reuses the same dual-backend LLM plumbing as the AI report,
  // but every question is answered live (no caching, unlike reports)
  const [chatMessages, setChatMessages] = useState([])  // [{ role: "user"|"assistant", content }]
  const [chatInput, setChatInput]       = useState("")
  const [chatLoading, setChatLoading]   = useState(false)
  const [chatError, setChatError]       = useState(null)
  const chatScrollRef = useRef(null)

  // Audit trail
  const [auditResult, setAuditResult]   = useState(null)
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditOpen, setAuditOpen]       = useState(false)

  // PDF export
  const [pdfExporting, setPdfExporting] = useState(false)
  const [pdfError, setPdfError]         = useState(null)

  // Scan comparison — nav-level panel, independent of the currently loaded scan
  const [compareOpen, setCompareOpen]     = useState(false)
  const [compareA, setCompareA]           = useState("")
  const [compareB, setCompareB]           = useState("")
  const [comparing, setComparing]         = useState(false)
  const [compareError, setCompareError]   = useState(null)
  const [compareResult, setCompareResult] = useState(null)

  const tableRef = useRef(null)
  const pollTimerRef = useRef(null)

  // Reset filter/page/report on new scan load.
  // Pattern: detect the change during render and adjust state immediately,
  // rather than in a useEffect — avoids an extra render pass and matches
  // React's documented guidance for "resetting state when a prop changes."
  const [prevScanId, setPrevScanId] = useState(scan?.id)
  if (scan?.id !== prevScanId) {
    setPrevScanId(scan?.id)
    setFilterSeverity("All")
    setSearchQuery("")
    setPage(1)
    setReport(null)
    setReportError(null)
    setChatMessages([])
    setChatError(null)
    setPdfError(null)
  }

  // Reset the displayed report when switching Local/Cloud — each backend has
  // its own independent cache now, so the old backend's text should never
  // linger on screen labeled under the new toggle. Same render-time pattern.
  const [prevBackendChoice, setPrevBackendChoice] = useState(backendChoice)
  if (backendChoice !== prevBackendChoice) {
    setPrevBackendChoice(backendChoice)
    setReport(null)
    setReportError(null)
  }

  // Fetch history on mount
  useEffect(() => {
    async function fetchHistory() {
      setLoadingList(true)
      try {
        const res = await fetch(`${API_BASE}/scans`)
        if (!res.ok) throw new Error("Could not load scan history")
        const data = await res.json()
        setPastScans(data.sort((a, b) => b.id - a.id))
      } catch (err) {
        console.error("History fetch failed:", err.message)
      } finally {
        setLoadingList(false)
      }
    }
    fetchHistory()
  }, [])

  // Safety net: if the component unmounts mid-scan (e.g. navigation), stop polling
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current)
    }
  }, [])

  // Auto-scroll the chat panel to the latest message
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight
    }
  }, [chatMessages, chatLoading])

  function normaliseScan(detail) {
    return {
      id:           detail.id,
      target:       detail.target_url,
      total:        detail.total_findings,
      high:         detail.high_count,
      medium:       detail.medium_count,
      low:          detail.low_count,
      info:         detail.info_count,
      findings:     detail.findings ?? [],
      timestamp:    detail.timestamp,
      recordHash:   detail.record_hash ?? null,
      previousHash: detail.previous_hash ?? null,
    }
  }

  async function loadPastScan(scanId) {
    setDropdownOpen(false)
    setLoadingPast(true)
    setError(null)
    setScan(null)
    try {
      const res = await fetch(`${API_BASE}/scan/${scanId}`)
      if (!res.ok) throw new Error(`Could not load scan #${scanId}`)
      const detail = await res.json()
      setScan(normaliseScan(detail))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoadingPast(false)
    }
  }

  // Polls /api/scan/<job_id>/status until it resolves to "complete" or "failed".
  // Resolves with the final status body on success; rejects with an Error on failure.
  function pollScanStatus(jobId) {
    return new Promise((resolve, reject) => {
      pollTimerRef.current = setInterval(async () => {
        try {
          const statusRes = await fetch(`${API_BASE}/scan/${jobId}/status`)
          const body = await statusRes.json().catch(() => ({}))

          if (!statusRes.ok) {
            throw new Error(body.error || `Status check failed (${statusRes.status})`)
          }

          if (body.status === "pending") {
            setPhase("Starting scan…")
            setProgress(2)

          } else if (body.status === "running") {
            setPhase(phaseLabel(body.phase))
            setProgress(computeProgress(body.phase, body.percent))

          } else if (body.status === "complete") {
            clearInterval(pollTimerRef.current)
            pollTimerRef.current = null
            resolve(body)

          } else if (body.status === "failed") {
            clearInterval(pollTimerRef.current)
            pollTimerRef.current = null
            reject(new Error(body.error || "Scan failed"))
          }
        } catch (err) {
          clearInterval(pollTimerRef.current)
          pollTimerRef.current = null
          reject(err)
        }
      }, POLL_INTERVAL_MS)
    })
  }

  async function handleScan() {
    if (!url || scanning) return
    setScanning(true)
    setProgress(0)
    setScan(null)
    setError(null)
    setPhase("Starting scan…")

    try {
      // 1. Kick off the background scan job
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: url }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || `Server error ${res.status}`)
      }
      const { job_id } = await res.json()

      // 2. Poll real ZAP progress until the job completes or fails
      const finalStatus = await pollScanStatus(job_id)

      // 3. Job's done — load the full findings for the resulting scan
      setProgress(97)
      setPhase("Loading findings…")

      const detailRes = await fetch(`${API_BASE}/scan/${finalStatus.scan_id}`)
      if (!detailRes.ok) throw new Error(`Could not load findings for scan ${finalStatus.scan_id}`)
      const detail = await detailRes.json()

      setProgress(100)
      setPhase("")
      setScan(normaliseScan(detail))

      setPastScans(prev => [
        { id: detail.id, target_url: detail.target_url, timestamp: detail.timestamp,
          total_findings: detail.total_findings, high_count: detail.high_count,
          medium_count: detail.medium_count, low_count: detail.low_count, info_count: detail.info_count },
        ...prev.filter(s => s.id !== detail.id),
      ])
    } catch (err) {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current)
        pollTimerRef.current = null
      }
      setError(err.message)
      setProgress(0)
      setPhase("")
    } finally {
      setScanning(false)
    }
  }

  async function fetchReport(regenerate = false) {
    if (!scan || reportLoading) return
    setReportLoading(true)
    setReportError(null)
    try {
      const params = new URLSearchParams({ backend: backendChoice })
      if (regenerate) params.set("regenerate", "true")
      const res = await fetch(`${API_BASE}/scan/${scan.id}/report?${params.toString()}`)
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        const msg = body.error ? `${body.error}${body.detail ? " — " + body.detail : ""}` : `Server error ${res.status}`
        throw new Error(msg)
      }
      setReport(body)
    } catch (err) {
      setReportError(err.message)
    } finally {
      setReportLoading(false)
    }
  }

  async function sendChatMessage() {
    const question = chatInput.trim()
    if (!question || !scan || chatLoading) return

    setChatError(null)
    setChatInput("")

    // Show the user's message immediately, before the network call resolves
    const userMessage = { role: "user", content: question }
    setChatMessages(prev => [...prev, userMessage])
    setChatLoading(true)

    try {
      // Send recent history (pre-this-message) so the model has follow-up context
      const history = chatMessages.slice(-6)

      const res = await fetch(`${API_BASE}/scan/${scan.id}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question, backend: backendChoice, history }),
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        const msg = body.error ? `${body.error}${body.detail ? " — " + body.detail : ""}` : `Server error ${res.status}`
        throw new Error(msg)
      }

      setChatMessages(prev => [...prev, { role: "assistant", content: body.answer, backend: body.backend }])
    } catch (err) {
      setChatError(err.message)
      // Roll back the optimistic user message's "pending" feel by leaving it
      // in place (it was a real send attempt) but surface the error clearly
    } finally {
      setChatLoading(false)
    }
  }

  async function verifyAudit() {
    if (auditLoading) return
    setAuditLoading(true)
    setAuditOpen(true)
    try {
      const res = await fetch(`${API_BASE}/audit/verify`)
      const body = await res.json()
      setAuditResult(body)
    } catch (err) {
      setAuditResult({ valid: false, issues: [{ detail: err.message }], total_scans: 0, verified_count: 0, legacy_count: 0 })
    } finally {
      setAuditLoading(false)
    }
  }

  async function exportPdf() {
    if (!scan || pdfExporting) return
    setPdfExporting(true)
    setPdfError(null)
    try {
      const res = await fetch(`${API_BASE}/scan/${scan.id}/export/pdf`)
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error || `Server error ${res.status}`)
      }
      const blob = await res.blob()
      const downloadUrl = window.URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = downloadUrl
      a.download = `secureqa-scan-${scan.id}-report.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(downloadUrl)
    } catch (err) {
      setPdfError(err.message)
    } finally {
      setPdfExporting(false)
    }
  }

  async function runCompare() {
    if (!compareA || !compareB || compareA === compareB || comparing) return
    setComparing(true)
    setCompareError(null)
    setCompareResult(null)
    try {
      const res = await fetch(`${API_BASE}/scans/compare?a=${compareA}&b=${compareB}`)
      const body = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(body.error || `Server error ${res.status}`)
      setCompareResult(body)
    } catch (err) {
      setCompareError(err.message)
    } finally {
      setComparing(false)
    }
  }

  const riskConfig = {
    High:          { color: "#f87171", bg: "rgba(248,113,113,0.08)", border: "rgba(248,113,113,0.2)", label: "High",   canonical: "High"   },
    Medium:        { color: "#fbbf24", bg: "rgba(251,191,36,0.08)",  border: "rgba(251,191,36,0.2)",  label: "Medium", canonical: "Medium" },
    Low:           { color: "#60a5fa", bg: "rgba(96,165,250,0.08)",  border: "rgba(96,165,250,0.2)",  label: "Low",    canonical: "Low"    },
    Info:          { color: "#94a3b8", bg: "rgba(148,163,184,0.08)", border: "rgba(148,163,184,0.2)", label: "Info",   canonical: "Info"   },
    Informational: { color: "#94a3b8", bg: "rgba(148,163,184,0.08)", border: "rgba(148,163,184,0.2)", label: "Info",   canonical: "Info"   },
  }
  function getRiskConfig(r) { return riskConfig[r] ?? riskConfig["Info"] }
  function getCanonical(r)  { return getRiskConfig(r).canonical }

  const filteredFindings = scan ? scan.findings.filter(f => {
    const riskStr   = f.risk ?? f.riskdesc ?? "Info"
    const canonical = getCanonical(riskStr)
    const matchSev  = filterSeverity === "All" || canonical === filterSeverity
    const name = (f.alert ?? f.name ?? "").toLowerCase()
    const desc = (f.description ?? f.desc ?? "").toLowerCase()
    const fUrl = (f.url ?? f.uri ?? "").toLowerCase()
    const q    = searchQuery.toLowerCase()
    const matchQ = !q || name.includes(q) || desc.includes(q) || fUrl.includes(q)
    return matchSev && matchQ
  }) : []

  const totalPages    = Math.max(1, Math.ceil(filteredFindings.length / PAGE_SIZE))
  const pagedFindings = filteredFindings.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  function applyFilter(sev) { setFilterSeverity(sev); setPage(1) }
  function applySearch(q)   { setSearchQuery(q);       setPage(1) }

  const pieData = scan ? [
    { name: "High",   value: scan.high,   color: "#f87171" },
    { name: "Medium", value: scan.medium, color: "#fbbf24" },
    { name: "Low",    value: scan.low,    color: "#60a5fa" },
    { name: "Info",   value: scan.info,   color: "#475569" },
  ].filter(d => d.value > 0) : []

  const barData = scan ? [
    { name: "High",   count: scan.high,   fill: "#f87171" },
    { name: "Medium", count: scan.medium, fill: "#fbbf24" },
    { name: "Low",    count: scan.low,    fill: "#60a5fa" },
    { name: "Info",   count: scan.info,   fill: "#475569" },
  ] : []

  const riskScore      = scan ? Math.min(10, Math.round((scan.high * 4 + scan.medium * 1.5 + scan.low * 0.5) / 60)) : 0
  const riskLabel      = riskScore >= 7 ? "Critical" : riskScore >= 4 ? "Moderate" : "Low Risk"
  const riskScoreColor = riskScore >= 7 ? "#f87171" : riskScore >= 4 ? "#fbbf24" : "#34d399"

  return (
    <div style={{ minHeight: "100vh", background: "#0d0d14", color: "#fff", fontFamily: "'Inter', system-ui, sans-serif" }}>

      <nav style={{ borderBottom: "1px solid rgba(255,255,255,0.06)", padding: "14px 28px", display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{ width: 32, height: 32, borderRadius: 10, background: "rgba(52,211,153,0.12)", border: "1px solid rgba(52,211,153,0.25)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Shield size={15} color="#34d399" />
        </div>
        <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: "-0.02em" }}>SecureQA <span style={{ color: "rgba(255,255,255,0.25)", fontWeight: 400 }}>Sentinel</span></span>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 16 }}>

          {/* Compare scans toggle */}
          <button
            onClick={() => setCompareOpen(o => !o)}
            style={{
              display: "flex", alignItems: "center", gap: 6,
              background: compareOpen ? "rgba(52,211,153,0.1)" : "rgba(255,255,255,0.04)",
              border: `1px solid ${compareOpen ? "rgba(52,211,153,0.25)" : "rgba(255,255,255,0.08)"}`,
              borderRadius: 8, padding: "5px 12px", cursor: "pointer",
            }}
          >
            <GitCompare size={13} color={compareOpen ? "#34d399" : "rgba(255,255,255,0.4)"} />
            <span style={{ fontSize: 12, color: compareOpen ? "#34d399" : "rgba(255,255,255,0.5)" }}>Compare Scans</span>
          </button>

          {/* Audit trail verify */}
          <div style={{ position: "relative" }}>
            <button
              onClick={verifyAudit}
              disabled={auditLoading}
              style={{ display: "flex", alignItems: "center", gap: 6, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: "5px 12px", cursor: auditLoading ? "wait" : "pointer" }}
            >
              {auditLoading
                ? <div style={{ width: 12, height: 12, borderRadius: "50%", border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#fff", animation: "spin 0.8s linear infinite" }} />
                : auditResult
                  ? (auditResult.valid ? <ShieldCheck size={13} color="#34d399" /> : <ShieldAlert size={13} color="#f87171" />)
                  : <ShieldCheck size={13} color="rgba(255,255,255,0.4)" />
              }
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>
                {auditLoading ? "Verifying…" : "Verify Audit Trail"}
              </span>
            </button>

            {auditOpen && auditResult && !auditLoading && (
              <div style={{ position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 50, background: "#13131a", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 12, minWidth: 300, padding: 16, boxShadow: "0 16px 48px rgba(0,0,0,0.6)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
                  {auditResult.valid
                    ? <ShieldCheck size={16} color="#34d399" />
                    : <ShieldAlert size={16} color="#f87171" />
                  }
                  <span style={{ fontSize: 13, fontWeight: 700, color: auditResult.valid ? "#34d399" : "#f87171" }}>
                    {auditResult.valid ? "Chain verified — no tampering" : "Tampering detected"}
                  </span>
                  <button onClick={() => setAuditOpen(false)} style={{ marginLeft: "auto", background: "none", border: "none", color: "rgba(255,255,255,0.3)", cursor: "pointer" }}><X size={13} /></button>
                </div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.4)", lineHeight: 1.7 }}>
                  <div>Total scans: {auditResult.total_scans ?? "—"}</div>
                  <div>Verified: {auditResult.verified_count ?? "—"}</div>
                  {auditResult.legacy_count > 0 && <div>Legacy (pre-audit): {auditResult.legacy_count}</div>}
                </div>
                {auditResult.issues?.length > 0 && (
                  <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                    {auditResult.issues.map((issue, i) => (
                      <div key={i} style={{ fontSize: 11, color: "#f87171", marginBottom: 6 }}>
                        {issue.scan_id && <strong>Scan #{issue.scan_id}: </strong>}{issue.type ? `[${issue.type}] ` : ""}{issue.detail}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#34d399", boxShadow: "0 0 8px #34d399" }} />
            <span style={{ fontSize: 12, color: "rgba(255,255,255,0.3)" }}>ZAP connected · v2.17.0</span>
          </div>
        </div>
      </nav>

      {auditOpen && <div onClick={() => setAuditOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />}

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "40px 28px" }}>

        <div style={{ marginBottom: 32 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <TrendingUp size={14} color="#34d399" />
            <span style={{ fontSize: 11, color: "#34d399", textTransform: "uppercase", letterSpacing: "0.1em", fontWeight: 600 }}>Vulnerability Scanner</span>
          </div>
          <h1 style={{ fontSize: 28, fontWeight: 800, letterSpacing: "-0.03em", margin: 0 }}>Security Analysis Dashboard</h1>
          <p style={{ color: "rgba(255,255,255,0.35)", fontSize: 13, marginTop: 6 }}>Automated OWASP vulnerability detection · AI-powered reporting</p>
        </div>

        {/* Scan comparison panel — nav-triggered, independent of the currently loaded scan */}
        {compareOpen && (
          <div style={{ marginBottom: 28, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, overflow: "hidden" }}>
            <div style={{ padding: "14px 20px", borderBottom: "1px solid rgba(255,255,255,0.05)", display: "flex", alignItems: "center", gap: 10 }}>
              <GitCompare size={14} color="#34d399" />
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", fontWeight: 600 }}>Compare Two Scans</span>
            </div>

            <div style={{ padding: "16px 20px", display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
              <select
                value={compareA}
                onChange={e => setCompareA(e.target.value)}
                style={{ flex: 1, minWidth: 200, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, padding: "9px 12px", fontSize: 13, color: "#fff", outline: "none" }}
              >
                <option value="" style={{ background: "#13131a" }}>Scan A (before)…</option>
                {pastScans.map(s => (
                  <option key={s.id} value={s.id} style={{ background: "#13131a" }}>
                    #{s.id} — {s.timestamp ? new Date(s.timestamp).toLocaleDateString() : "—"} — {s.total_findings} findings
                  </option>
                ))}
              </select>

              <ArrowRight size={16} color="rgba(255,255,255,0.25)" />

              <select
                value={compareB}
                onChange={e => setCompareB(e.target.value)}
                style={{ flex: 1, minWidth: 200, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, padding: "9px 12px", fontSize: 13, color: "#fff", outline: "none" }}
              >
                <option value="" style={{ background: "#13131a" }}>Scan B (after)…</option>
                {pastScans.map(s => (
                  <option key={s.id} value={s.id} style={{ background: "#13131a" }}>
                    #{s.id} — {s.timestamp ? new Date(s.timestamp).toLocaleDateString() : "—"} — {s.total_findings} findings
                  </option>
                ))}
              </select>

              <button
                onClick={runCompare}
                disabled={!compareA || !compareB || compareA === compareB || comparing}
                style={{
                  display: "flex", alignItems: "center", gap: 6,
                  padding: "9px 18px", borderRadius: 10, fontSize: 13, fontWeight: 700,
                  background: (!compareA || !compareB || compareA === compareB) ? "rgba(52,211,153,0.15)" : "#34d399",
                  border: "none", color: (!compareA || !compareB || compareA === compareB) ? "rgba(0,0,0,0.4)" : "#000",
                  cursor: (!compareA || !compareB || compareA === compareB || comparing) ? "not-allowed" : "pointer",
                }}
              >
                {comparing
                  ? <><div style={{ width: 11, height: 11, borderRadius: "50%", border: "2px solid rgba(0,0,0,0.2)", borderTopColor: "#000", animation: "spin 0.8s linear infinite" }} />Comparing…</>
                  : "Compare"
                }
              </button>
            </div>

            {compareA && compareB && compareA === compareB && (
              <div style={{ margin: "0 20px 16px", fontSize: 12, color: "#fbbf24" }}>Pick two different scans to compare.</div>
            )}

            {compareError && (
              <div style={{ margin: "0 20px 16px", background: "rgba(248,113,113,0.08)", border: "1px solid rgba(248,113,113,0.2)", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", gap: 10 }}>
                <AlertCircle size={14} color="#f87171" />
                <span style={{ fontSize: 12, color: "#f87171" }}>{compareError}</span>
              </div>
            )}

            {compareResult && (
              <div style={{ padding: "0 20px 20px" }}>

                {/* Summary counts */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 18 }}>
                  <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "14px 16px" }}>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginBottom: 4 }}>New</div>
                    <div style={{ fontSize: 22, fontWeight: 800, color: "#f87171" }}>{compareResult.summary.new_count}</div>
                  </div>
                  <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "14px 16px" }}>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginBottom: 4 }}>Resolved</div>
                    <div style={{ fontSize: 22, fontWeight: 800, color: "#34d399" }}>{compareResult.summary.resolved_count}</div>
                  </div>
                  <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "14px 16px" }}>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginBottom: 4 }}>Persistent</div>
                    <div style={{ fontSize: 22, fontWeight: 800, color: "#fff" }}>{compareResult.summary.persistent_count}</div>
                  </div>
                </div>

                {/* New */}
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                    <AlertTriangle size={13} color="#f87171" />
                    <span style={{ fontSize: 12, fontWeight: 700, color: "#f87171" }}>New</span>
                  </div>
                  {compareResult.new.length === 0 ? (
                    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10, padding: "12px 16px", fontSize: 12, color: "rgba(255,255,255,0.25)", textAlign: "center" }}>
                      Nothing new between these scans.
                    </div>
                  ) : (
                    <div style={{ border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, overflow: "hidden" }}>
                      {compareResult.new.map((f, i) => {
                        const rc = getRiskConfig(f.severity)
                        return (
                          <div key={`${f.name}-${f.cwe}-${i}`} style={{ padding: "10px 14px", borderBottom: i < compareResult.new.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", display: "flex", alignItems: "center", gap: 12 }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontSize: 13, color: "rgba(255,255,255,0.85)" }}>{f.name}</div>
                              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)" }}>{f.cwe || "No CWE"} · {f.instance_count} instance{f.instance_count === 1 ? "" : "s"}</div>
                            </div>
                            <div style={{ background: rc.bg, border: `1px solid ${rc.border}`, borderRadius: 6, padding: "3px 9px", flexShrink: 0 }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: rc.color }}>{rc.label}</span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>

                {/* Resolved */}
                <div style={{ marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                    <CheckCircle size={13} color="#34d399" />
                    <span style={{ fontSize: 12, fontWeight: 700, color: "#34d399" }}>Resolved</span>
                  </div>
                  {compareResult.resolved.length === 0 ? (
                    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10, padding: "12px 16px", fontSize: 12, color: "rgba(255,255,255,0.25)", textAlign: "center" }}>
                      Nothing resolved between these scans.
                    </div>
                  ) : (
                    <div style={{ border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, overflow: "hidden" }}>
                      {compareResult.resolved.map((f, i) => {
                        const rc = getRiskConfig(f.severity)
                        return (
                          <div key={`${f.name}-${f.cwe}-${i}`} style={{ padding: "10px 14px", borderBottom: i < compareResult.resolved.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", display: "flex", alignItems: "center", gap: 12 }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontSize: 13, color: "rgba(255,255,255,0.85)" }}>{f.name}</div>
                              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)" }}>{f.cwe || "No CWE"} · {f.instance_count} instance{f.instance_count === 1 ? "" : "s"}</div>
                            </div>
                            <div style={{ background: rc.bg, border: `1px solid ${rc.border}`, borderRadius: 6, padding: "3px 9px", flexShrink: 0 }}>
                              <span style={{ fontSize: 11, fontWeight: 700, color: rc.color }}>{rc.label}</span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>

                {/* Persistent */}
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
                    <Minus size={13} color="rgba(255,255,255,0.4)" />
                    <span style={{ fontSize: 12, fontWeight: 700, color: "rgba(255,255,255,0.5)" }}>Persistent</span>
                  </div>
                  {compareResult.persistent.length === 0 ? (
                    <div style={{ background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 10, padding: "12px 16px", fontSize: 12, color: "rgba(255,255,255,0.25)", textAlign: "center" }}>
                      No shared findings between these scans.
                    </div>
                  ) : (
                    <div style={{ border: "1px solid rgba(255,255,255,0.07)", borderRadius: 10, overflow: "hidden" }}>
                      {compareResult.persistent.map((f, i) => {
                        const rcA = getRiskConfig(f.severity_a)
                        const rcB = getRiskConfig(f.severity_b)
                        return (
                          <div key={`${f.name}-${f.cwe}-${i}`} style={{ padding: "10px 14px", borderBottom: i < compareResult.persistent.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", display: "flex", alignItems: "center", gap: 12 }}>
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ fontSize: 13, color: "rgba(255,255,255,0.85)" }}>{f.name}</div>
                              <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)" }}>{f.cwe || "No CWE"} · {f.instance_count_a} → {f.instance_count_b} instances</div>
                            </div>
                            {f.severity_changed ? (
                              <div style={{ display: "flex", alignItems: "center", gap: 5, flexShrink: 0 }}>
                                <div style={{ background: rcA.bg, border: `1px solid ${rcA.border}`, borderRadius: 6, padding: "3px 9px" }}>
                                  <span style={{ fontSize: 11, fontWeight: 700, color: rcA.color }}>{rcA.label}</span>
                                </div>
                                <ArrowRight size={11} color="rgba(255,255,255,0.3)" />
                                <div style={{ background: rcB.bg, border: `1px solid ${rcB.border}`, borderRadius: 6, padding: "3px 9px" }}>
                                  <span style={{ fontSize: 11, fontWeight: 700, color: rcB.color }}>{rcB.label}</span>
                                </div>
                              </div>
                            ) : (
                              <div style={{ background: rcB.bg, border: `1px solid ${rcB.border}`, borderRadius: 6, padding: "3px 9px", flexShrink: 0 }}>
                                <span style={{ fontSize: 11, fontWeight: 700, color: rcB.color }}>{rcB.label}</span>
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Input row */}
        <div style={{ display: "flex", gap: 10, marginBottom: 28, alignItems: "stretch" }}>
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleScan()}
            placeholder="http://host.docker.internal:3000"
            style={{ flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, padding: "12px 16px", fontSize: 13, color: "#fff", outline: "none" }}
          />

          {/* Past scans dropdown */}
          <div style={{ position: "relative" }}>
            <button
              onClick={() => setDropdownOpen(o => !o)}
              disabled={loadingList || scanning}
              style={{ height: "100%", padding: "0 16px", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, fontSize: 13, color: "rgba(255,255,255,0.6)", cursor: loadingList || scanning ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: 7, whiteSpace: "nowrap", opacity: loadingList ? 0.4 : 1 }}
            >
              <History size={13} />
              {loadingList ? "Loading…" : `Past scans${pastScans.length ? ` (${pastScans.length})` : ""}`}
              <ChevronDown size={12} style={{ opacity: 0.4, transform: dropdownOpen ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.2s" }} />
            </button>

            {dropdownOpen && (
              <div style={{ position: "absolute", top: "calc(100% + 6px)", right: 0, zIndex: 50, background: "#13131a", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 12, minWidth: 340, maxHeight: 320, overflowY: "auto", boxShadow: "0 16px 48px rgba(0,0,0,0.6)" }}>
                <div style={{ padding: "10px 16px 8px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                  <span style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", textTransform: "uppercase", letterSpacing: "0.08em" }}>Scan history</span>
                </div>
                {pastScans.length === 0 ? (
                  <div style={{ padding: "20px 16px", textAlign: "center", color: "rgba(255,255,255,0.25)", fontSize: 13 }}>No past scans found.</div>
                ) : (
                  pastScans.map((s, i) => (
                    <div key={s.id} onClick={() => loadPastScan(s.id)}
                      style={{ padding: "11px 16px", borderBottom: i < pastScans.length - 1 ? "1px solid rgba(255,255,255,0.05)" : "none", cursor: "pointer" }}
                      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
                        <span style={{ fontSize: 10, color: "#34d399", fontWeight: 700, background: "rgba(52,211,153,0.1)", border: "1px solid rgba(52,211,153,0.2)", borderRadius: 4, padding: "1px 6px", flexShrink: 0 }}>#{s.id}</span>
                        <span style={{ fontSize: 12, color: "rgba(255,255,255,0.7)", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.target_url}</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 5, flexWrap: "wrap" }}>
                        {s.high_count   > 0 && <span style={{ fontSize: 10, color: "#f87171", background: "rgba(248,113,113,0.1)", borderRadius: 4, padding: "1px 6px" }}>{s.high_count}H</span>}
                        {s.medium_count > 0 && <span style={{ fontSize: 10, color: "#fbbf24", background: "rgba(251,191,36,0.1)",  borderRadius: 4, padding: "1px 6px" }}>{s.medium_count}M</span>}
                        {s.low_count    > 0 && <span style={{ fontSize: 10, color: "#60a5fa", background: "rgba(96,165,250,0.1)",  borderRadius: 4, padding: "1px 6px" }}>{s.low_count}L</span>}
                        {s.info_count   > 0 && <span style={{ fontSize: 10, color: "#94a3b8", background: "rgba(148,163,184,0.1)", borderRadius: 4, padding: "1px 6px" }}>{s.info_count}I</span>}
                        <span style={{ marginLeft: "auto", fontSize: 10, color: "rgba(255,255,255,0.2)" }}>{s.timestamp ? new Date(s.timestamp).toLocaleString() : "—"}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          {dropdownOpen && <div onClick={() => setDropdownOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 40 }} />}

          <button onClick={handleScan} disabled={scanning || !url}
            style={{ padding: "12px 24px", background: scanning ? "rgba(52,211,153,0.3)" : "#34d399", borderRadius: 12, fontSize: 13, fontWeight: 700, color: "#000", border: "none", cursor: scanning ? "not-allowed" : "pointer", display: "flex", alignItems: "center", gap: 7, opacity: !url ? 0.4 : 1 }}>
            <Zap size={14} />
            {scanning ? "Scanning…" : "Run Scan"}
          </button>
        </div>

        {error && (
          <div style={{ marginBottom: 20, background: "rgba(248,113,113,0.08)", border: "1px solid rgba(248,113,113,0.2)", borderRadius: 12, padding: "13px 18px", display: "flex", alignItems: "center", gap: 10 }}>
            <AlertCircle size={15} color="#f87171" />
            <span style={{ fontSize: 13, color: "#f87171" }}>{error}</span>
            <button onClick={() => setError(null)} style={{ marginLeft: "auto", background: "none", border: "none", color: "rgba(248,113,113,0.5)", cursor: "pointer", fontSize: 18, lineHeight: 1 }}>x</button>
          </div>
        )}

        {loadingPast && (
          <div style={{ marginBottom: 20, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: "16px 20px", display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 14, height: 14, borderRadius: "50%", border: "2px solid rgba(52,211,153,0.3)", borderTopColor: "#34d399", animation: "spin 0.8s linear infinite" }} />
            <span style={{ fontSize: 13, color: "rgba(255,255,255,0.35)" }}>Loading scan results…</span>
          </div>
        )}

        {scanning && (
          <div style={{ marginBottom: 28, background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: "16px 20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
              <span style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>{phase}</span>
              <span style={{ fontSize: 12, color: "#34d399", fontWeight: 600 }}>{Math.round(progress)}%</span>
            </div>
            <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 4, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${progress}%`, background: "linear-gradient(90deg, #34d399, #60a5fa)", borderRadius: 4, transition: "width 0.3s ease" }} />
            </div>
            <div style={{ display: "flex", gap: 16, marginTop: 12 }}>
              {["Spider crawl", "Active scan", "Alert fetch", "AI report"].map((s, i) => (
                <div key={s} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                  <div style={{ width: 5, height: 5, borderRadius: "50%", background: progress > i * 25 ? "#34d399" : "rgba(255,255,255,0.15)" }} />
                  <span style={{ fontSize: 11, color: progress > i * 25 ? "rgba(255,255,255,0.5)" : "rgba(255,255,255,0.2)" }}>{s}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

        {scan && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

            <div style={{ fontSize: 11, color: "rgba(255,255,255,0.2)", display: "flex", gap: 16, flexWrap: "wrap", alignItems: "center" }}>
              <span>Scan ID <span style={{ color: "rgba(255,255,255,0.45)" }}>#{scan.id}</span></span>
              <span>Target <span style={{ color: "rgba(255,255,255,0.45)", fontFamily: "monospace" }}>{scan.target}</span></span>
              {scan.timestamp && <span>Completed <span style={{ color: "rgba(255,255,255,0.45)" }}>{new Date(scan.timestamp).toLocaleString()}</span></span>}
              {scan.recordHash && (
                <span title={scan.recordHash} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <ShieldCheck size={11} color="#34d399" />
                  <span style={{ fontFamily: "monospace", color: "rgba(52,211,153,0.6)" }}>{scan.recordHash.slice(0, 10)}…</span>
                </span>
              )}

              <button
                onClick={exportPdf}
                disabled={pdfExporting}
                style={{
                  marginLeft: "auto", display: "flex", alignItems: "center", gap: 6,
                  padding: "5px 12px", borderRadius: 8, fontSize: 11, fontWeight: 600,
                  background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                  color: "rgba(255,255,255,0.5)", cursor: pdfExporting ? "wait" : "pointer",
                }}
              >
                {pdfExporting
                  ? <><div style={{ width: 11, height: 11, borderRadius: "50%", border: "2px solid rgba(255,255,255,0.2)", borderTopColor: "#fff", animation: "spin 0.8s linear infinite" }} />Exporting…</>
                  : <><Download size={12} />Export PDF</>
                }
              </button>
            </div>

            {pdfError && (
              <div style={{ background: "rgba(248,113,113,0.08)", border: "1px solid rgba(248,113,113,0.2)", borderRadius: 12, padding: "13px 18px", display: "flex", alignItems: "center", gap: 10 }}>
                <AlertCircle size={15} color="#f87171" />
                <span style={{ fontSize: 13, color: "#f87171" }}>{pdfError}</span>
                <button onClick={() => setPdfError(null)} style={{ marginLeft: "auto", background: "none", border: "none", color: "rgba(248,113,113,0.5)", cursor: "pointer", fontSize: 18, lineHeight: 1 }}>x</button>
              </div>
            )}

            <div style={{ display: "grid", gridTemplateColumns: "160px 1fr 1fr", gap: 16 }}>
              <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "20px 16px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 6 }}>
                <span style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", textTransform: "uppercase", letterSpacing: "0.08em" }}>Risk Score</span>
                <span style={{ fontSize: 52, fontWeight: 900, color: riskScoreColor, letterSpacing: "-0.04em", lineHeight: 1 }}>{riskScore}</span>
                <span style={{ fontSize: 10, color: "rgba(255,255,255,0.3)" }}>out of 10</span>
                <div style={{ marginTop: 4, background: `${riskScoreColor}15`, border: `1px solid ${riskScoreColor}30`, borderRadius: 20, padding: "3px 10px" }}>
                  <span style={{ fontSize: 11, color: riskScoreColor, fontWeight: 600 }}>{riskLabel}</span>
                </div>
              </div>

              <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "16px 20px" }}>
                <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 4, fontWeight: 600 }}>Severity Distribution</div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.2)", marginBottom: 12 }}>Breakdown of {scan.total} findings</div>
                <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
                  <ResponsiveContainer width={110} height={110}>
                    <PieChart>
                      <Pie data={pieData} cx="50%" cy="50%" innerRadius={30} outerRadius={50} paddingAngle={3} dataKey="value">
                        {pieData.map((entry, i) => <Cell key={i} fill={entry.color} stroke="transparent" />)}
                      </Pie>
                      <Tooltip content={<CustomTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                    {pieData.map(d => (
                      <div key={d.name} style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                        <span style={{ fontSize: 12, color: "rgba(255,255,255,0.5)" }}>{d.name}</span>
                        <span style={{ fontSize: 12, color: "#fff", fontWeight: 600, marginLeft: "auto", paddingLeft: 12 }}>{d.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, padding: "16px 20px" }}>
                <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 4, fontWeight: 600 }}>Findings by Severity</div>
                <div style={{ fontSize: 11, color: "rgba(255,255,255,0.2)", marginBottom: 12 }}>Count per category</div>
                <ResponsiveContainer width="100%" height={110}>
                  <BarChart data={barData} barSize={28} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
                    <XAxis dataKey="name" tick={{ fill: "rgba(255,255,255,0.3)", fontSize: 11 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: "rgba(255,255,255,0.2)", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(255,255,255,0.03)" }} />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {barData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10 }}>
              {[
                { label: "Total Findings", value: scan.total,  color: "#fff",    icon: <Shield size={13}/> },
                { label: "Medium Risk",    value: scan.medium, color: "#fbbf24", icon: <AlertTriangle size={13}/> },
                { label: "Low Risk",       value: scan.low,    color: "#60a5fa", icon: <Info size={13}/> },
                { label: "Informational",  value: scan.info,   color: "#94a3b8", icon: <CheckCircle size={13}/> },
              ].map(s => (
                <div key={s.label} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 12, padding: "14px 16px", display: "flex", alignItems: "center", gap: 12 }}>
                  <div style={{ color: s.color, opacity: 0.6 }}>{s.icon}</div>
                  <div>
                    <div style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", marginBottom: 2 }}>{s.label}</div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: s.color, letterSpacing: "-0.02em" }}>{s.value}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Findings table with filter + pagination */}
            <div ref={tableRef} style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, overflow: "hidden" }}>

              {/* Table header */}
              <div style={{ padding: "14px 20px", borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                  <Clock size={13} color="rgba(255,255,255,0.25)" />
                  <span style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", fontWeight: 600 }}>Findings — {scan.target}</span>
                  <div style={{ marginLeft: "auto", background: "rgba(255,255,255,0.05)", borderRadius: 20, padding: "2px 10px" }}>
                    <span style={{ fontSize: 11, color: "rgba(255,255,255,0.3)" }}>
                      {filteredFindings.length !== scan.total
                        ? `${filteredFindings.length} of ${scan.total}`
                        : `${scan.total} total`}
                    </span>
                  </div>
                </div>

                {/* Filter pills + search */}
                <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <div style={{ display: "flex", gap: 4 }}>
                    {SEVERITY_FILTERS.map(sev => {
                      const active = filterSeverity === sev
                      const cfg    = sev !== "All" ? riskConfig[sev] : null
                      return (
                        <button key={sev} onClick={() => applyFilter(sev)}
                          style={{
                            padding: "4px 10px", borderRadius: 20, fontSize: 11, fontWeight: 600,
                            cursor: "pointer", border: "1px solid",
                            background:   active ? (cfg ? cfg.bg   : "rgba(255,255,255,0.08)") : "transparent",
                            borderColor:  active ? (cfg ? cfg.border: "rgba(255,255,255,0.2)" ) : "rgba(255,255,255,0.08)",
                            color:        active ? (cfg ? cfg.color : "#fff"                  ) : "rgba(255,255,255,0.3)",
                            transition:   "all 0.15s",
                          }}>
                          {sev}
                        </button>
                      )
                    })}
                  </div>

                  <div style={{ marginLeft: "auto", position: "relative", display: "flex", alignItems: "center" }}>
                    <Search size={12} color="rgba(255,255,255,0.25)" style={{ position: "absolute", left: 10, pointerEvents: "none" }} />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={e => applySearch(e.target.value)}
                      placeholder="Search findings…"
                      style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: "5px 28px", fontSize: 12, color: "#fff", outline: "none", width: 180 }}
                    />
                    {searchQuery && (
                      <button onClick={() => applySearch("")}
                        style={{ position: "absolute", right: 8, background: "none", border: "none", color: "rgba(255,255,255,0.3)", cursor: "pointer", padding: 0, lineHeight: 1 }}>
                        <X size={11} />
                      </button>
                    )}
                  </div>
                </div>
              </div>

              {/* Rows */}
              {filteredFindings.length === 0 ? (
                <div style={{ padding: "32px 20px", textAlign: "center", color: "rgba(255,255,255,0.2)", fontSize: 13 }}>
                  {searchQuery || filterSeverity !== "All" ? "No findings match the current filter." : "No findings recorded for this scan."}
                </div>
              ) : (
                pagedFindings.map((f, i) => {
                  const riskStr = f.risk ?? f.riskdesc ?? "Info"
                  const name    = f.alert ?? f.name ?? "Unknown"
                  const desc    = f.description ?? f.desc ?? ""
                  const fUrl    = f.url ?? f.uri ?? ""
                  const rc      = getRiskConfig(riskStr)
                  return (
                    <div key={i}
                      style={{ padding: "13px 20px", borderBottom: i < pagedFindings.length - 1 ? "1px solid rgba(255,255,255,0.04)" : "none", display: "flex", alignItems: "center", gap: 14 }}
                      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.02)"}
                      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                    >
                      <div style={{ background: rc.bg, border: `1px solid ${rc.border}`, borderRadius: 6, padding: "3px 9px", flexShrink: 0 }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: rc.color }}>{rc.label}</span>
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 13, color: "rgba(255,255,255,0.85)", fontWeight: 500, marginBottom: 2 }}>{name}</div>
                        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{desc}</div>
                      </div>
                      <div style={{ fontSize: 11, color: "rgba(255,255,255,0.2)", fontFamily: "monospace", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{fUrl}</div>
                    </div>
                  )
                })
              )}

              {/* Pagination */}
              {totalPages > 1 && (
                <div style={{ padding: "12px 20px", borderTop: "1px solid rgba(255,255,255,0.05)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 11, color: "rgba(255,255,255,0.2)" }}>
                    Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filteredFindings.length)} of {filteredFindings.length}
                  </span>
                  <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
                    <button onClick={() => { setPage(p => Math.max(1, p - 1)); tableRef.current?.scrollIntoView({ behavior: "smooth" }) }}
                      disabled={page === 1}
                      style={{ padding: "4px 12px", borderRadius: 8, fontSize: 12, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: page === 1 ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)", cursor: page === 1 ? "not-allowed" : "pointer" }}>
                      Prev
                    </button>

                    {Array.from({ length: totalPages }, (_, i) => i + 1)
                      .filter(n => n === 1 || n === totalPages || Math.abs(n - page) <= 1)
                      .reduce((acc, n, idx, arr) => { if (idx > 0 && n - arr[idx-1] > 1) acc.push("…"); acc.push(n); return acc }, [])
                      .map((n, i) =>
                        n === "…"
                          ? <span key={`e${i}`} style={{ padding: "4px 4px", fontSize: 12, color: "rgba(255,255,255,0.2)" }}>…</span>
                          : <button key={n} onClick={() => { setPage(n); tableRef.current?.scrollIntoView({ behavior: "smooth" }) }}
                              style={{ padding: "4px 10px", borderRadius: 8, fontSize: 12, background: page === n ? "#34d399" : "rgba(255,255,255,0.04)", border: `1px solid ${page === n ? "#34d399" : "rgba(255,255,255,0.08)"}`, color: page === n ? "#000" : "rgba(255,255,255,0.5)", fontWeight: page === n ? 700 : 400, cursor: "pointer" }}>
                              {n}
                            </button>
                      )
                    }

                    <button onClick={() => { setPage(p => Math.min(totalPages, p + 1)); tableRef.current?.scrollIntoView({ behavior: "smooth" }) }}
                      disabled={page === totalPages}
                      style={{ padding: "4px 12px", borderRadius: 8, fontSize: 12, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", color: page === totalPages ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)", cursor: page === totalPages ? "not-allowed" : "pointer" }}>
                      Next
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* AI Report panel */}
            <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, overflow: "hidden" }}>
              <div style={{ padding: "14px 20px", borderBottom: report ? "1px solid rgba(255,255,255,0.05)" : "none", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <Sparkles size={14} color="#34d399" />
                <span style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", fontWeight: 600 }}>AI Report</span>

                {/* Local / Cloud backend toggle */}
                <div style={{ display: "flex", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: 2 }}>
                  {[{ id: "ollama", label: "Local" }, { id: "groq", label: "Cloud" }].map(opt => (
                    <button
                      key={opt.id}
                      onClick={() => setBackendChoice(opt.id)}
                      disabled={reportLoading}
                      style={{
                        padding: "3px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, border: "none",
                        cursor: reportLoading ? "not-allowed" : "pointer",
                        background: backendChoice === opt.id ? "#34d399" : "transparent",
                        color: backendChoice === opt.id ? "#000" : "rgba(255,255,255,0.4)",
                      }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>

                {report?.backend && (
                  <span style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", fontFamily: "monospace" }}>
                    via {report.backend}
                  </span>
                )}
                {report?.cached && (
                  <span style={{ fontSize: 10, color: "rgba(255,255,255,0.25)", background: "rgba(255,255,255,0.05)", borderRadius: 20, padding: "2px 8px" }}>cached</span>
                )}
                {report?.generated_at && (
                  <span style={{ fontSize: 10, color: "rgba(255,255,255,0.2)" }}>
                    {new Date(report.generated_at).toLocaleString()}
                  </span>
                )}

                <button
                  onClick={() => fetchReport(!!report)}
                  disabled={reportLoading}
                  style={{
                    marginLeft: "auto", display: "flex", alignItems: "center", gap: 6,
                    padding: "6px 14px", borderRadius: 8, fontSize: 12, fontWeight: 600,
                    background: reportLoading ? "rgba(52,211,153,0.15)" : "rgba(52,211,153,0.1)",
                    border: "1px solid rgba(52,211,153,0.25)", color: "#34d399",
                    cursor: reportLoading ? "wait" : "pointer",
                  }}
                >
                  {reportLoading
                    ? <><div style={{ width: 11, height: 11, borderRadius: "50%", border: "2px solid rgba(52,211,153,0.3)", borderTopColor: "#34d399", animation: "spin 0.8s linear infinite" }} />Generating…</>
                    : report
                      ? <><RefreshCw size={12} />Regenerate</>
                      : <><FileText size={12} />Generate AI Report</>
                  }
                </button>
              </div>

              {reportError && (
                <div style={{ margin: 16, background: "rgba(248,113,113,0.08)", border: "1px solid rgba(248,113,113,0.2)", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", gap: 10 }}>
                  <AlertCircle size={14} color="#f87171" />
                  <span style={{ fontSize: 12, color: "#f87171" }}>{reportError}</span>
                </div>
              )}

              {report?.report_text && (
                <div style={{
                  padding: "18px 22px", maxHeight: 420, overflowY: "auto",
                  fontSize: 13, lineHeight: 1.7, color: "rgba(255,255,255,0.75)",
                  whiteSpace: "pre-wrap", fontFamily: "'Inter', system-ui, sans-serif",
                }}>
                  {report.report_text}
                </div>
              )}

              {!report && !reportLoading && !reportError && (
                <div style={{ padding: "28px 20px", textAlign: "center", color: "rgba(255,255,255,0.2)", fontSize: 12 }}>
                  Generate a plain-English summary of these findings using a local AI model.
                </div>
              )}
            </div>

            {/* Chatbot Q&A panel */}
            <div style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)", borderRadius: 16, overflow: "hidden" }}>
              <div style={{ padding: "14px 20px", borderBottom: "1px solid rgba(255,255,255,0.05)", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <MessageCircle size={14} color="#34d399" />
                <span style={{ fontSize: 12, color: "rgba(255,255,255,0.35)", fontWeight: 600 }}>Ask About These Findings</span>

                {/* Same Local/Cloud toggle as the report panel — shared backend choice */}
                <div style={{ display: "flex", background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: 2 }}>
                  {[{ id: "ollama", label: "Local" }, { id: "groq", label: "Cloud" }].map(opt => (
                    <button
                      key={opt.id}
                      onClick={() => setBackendChoice(opt.id)}
                      disabled={chatLoading}
                      style={{
                        padding: "3px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600, border: "none",
                        cursor: chatLoading ? "not-allowed" : "pointer",
                        background: backendChoice === opt.id ? "#34d399" : "transparent",
                        color: backendChoice === opt.id ? "#000" : "rgba(255,255,255,0.4)",
                      }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>

                {chatMessages.length > 0 && (
                  <button
                    onClick={() => { setChatMessages([]); setChatError(null) }}
                    disabled={chatLoading}
                    style={{ marginLeft: "auto", background: "none", border: "none", color: "rgba(255,255,255,0.25)", fontSize: 11, cursor: chatLoading ? "not-allowed" : "pointer" }}
                  >
                    Clear chat
                  </button>
                )}
              </div>

              {/* Message list */}
              <div ref={chatScrollRef} style={{ maxHeight: 320, minHeight: chatMessages.length ? 120 : 0, overflowY: "auto", padding: chatMessages.length ? "16px 20px" : 0, display: "flex", flexDirection: "column", gap: 12 }}>
                {chatMessages.length === 0 && !chatLoading && (
                  <div style={{ padding: "28px 20px", textAlign: "center", color: "rgba(255,255,255,0.2)", fontSize: 12 }}>
                    Ask a follow-up question, e.g. "Which finding should I fix first?"
                  </div>
                )}

                {chatMessages.map((m, i) => (
                  <div key={i} style={{ display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start" }}>
                    <div style={{
                      maxWidth: "80%",
                      background: m.role === "user" ? "rgba(52,211,153,0.12)" : "rgba(255,255,255,0.04)",
                      border: `1px solid ${m.role === "user" ? "rgba(52,211,153,0.25)" : "rgba(255,255,255,0.08)"}`,
                      borderRadius: 12,
                      padding: "9px 13px",
                      fontSize: 13,
                      lineHeight: 1.6,
                      color: "rgba(255,255,255,0.85)",
                      whiteSpace: "pre-wrap",
                    }}>
                      {m.content}
                      {m.role === "assistant" && m.backend && (
                        <div style={{ marginTop: 5, fontSize: 10, color: "rgba(255,255,255,0.25)", fontFamily: "monospace" }}>via {m.backend}</div>
                      )}
                    </div>
                  </div>
                ))}

                {chatLoading && (
                  <div style={{ display: "flex", justifyContent: "flex-start" }}>
                    <div style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 12, padding: "9px 13px", display: "flex", alignItems: "center", gap: 8 }}>
                      <div style={{ width: 11, height: 11, borderRadius: "50%", border: "2px solid rgba(52,211,153,0.3)", borderTopColor: "#34d399", animation: "spin 0.8s linear infinite" }} />
                      <span style={{ fontSize: 12, color: "rgba(255,255,255,0.4)" }}>
                        {backendChoice === "ollama" ? "Thinking… (local model, can take ~2 min)" : "Thinking…"}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {chatError && (
                <div style={{ margin: "0 16px 16px", background: "rgba(248,113,113,0.08)", border: "1px solid rgba(248,113,113,0.2)", borderRadius: 10, padding: "12px 16px", display: "flex", alignItems: "center", gap: 10 }}>
                  <AlertCircle size={14} color="#f87171" />
                  <span style={{ fontSize: 12, color: "#f87171" }}>{chatError}</span>
                </div>
              )}

              {/* Input row */}
              <div style={{ display: "flex", gap: 8, padding: "14px 20px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
                <input
                  type="text"
                  value={chatInput}
                  onChange={e => setChatInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendChatMessage()}
                  disabled={chatLoading}
                  placeholder="Ask about these findings…"
                  style={{ flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 10, padding: "9px 14px", fontSize: 13, color: "#fff", outline: "none" }}
                />
                <button
                  onClick={sendChatMessage}
                  disabled={chatLoading || !chatInput.trim()}
                  style={{
                    display: "flex", alignItems: "center", gap: 6,
                    padding: "9px 16px", borderRadius: 10, fontSize: 13, fontWeight: 600,
                    background: chatLoading || !chatInput.trim() ? "rgba(52,211,153,0.15)" : "#34d399",
                    border: "none", color: chatLoading || !chatInput.trim() ? "rgba(0,0,0,0.4)" : "#000",
                    cursor: chatLoading || !chatInput.trim() ? "not-allowed" : "pointer",
                  }}
                >
                  <Send size={13} />
                  Send
                </button>
              </div>
            </div>

          </div>
        )}
      </div>
    </div>
  )
}