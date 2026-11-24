"""Autonomous SOC Triage Console v2.0 — Light-Mode CyberSec UI (Docker & Streamlit Cloud Ready)."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pandas as pd
import streamlit as st

# MUST be the very first Streamlit command before accessing st.secrets or st.cache_resource
st.set_page_config(
    page_title="SOC Triage Console",
    layout="wide",
    initial_sidebar_state="expanded",
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _sync_streamlit_secrets_to_env() -> None:
    """Mirror Streamlit Cloud st.secrets into os.environ only when a secrets.toml file exists."""
    candidate_paths = (
        Path.home() / ".streamlit" / "secrets.toml",
        PROJECT_ROOT / ".streamlit" / "secrets.toml",
        Path("/app/.streamlit/secrets.toml"),
    )
    if not any(path.is_file() for path in candidate_paths):
        return
    try:
        for key, value in st.secrets.items():
            if isinstance(value, (str, int, float, bool)) and key not in os.environ:
                os.environ[str(key)] = str(value)
    except Exception:
        pass


_sync_streamlit_secrets_to_env()

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
SAMPLE_LOGS_DIR = Path(
    os.getenv("SAMPLE_LOGS_DIR", str(PROJECT_ROOT / "data" / "sample_logs"))
).resolve()
PLAYBOOKS_DIR = Path(
    os.getenv("PLAYBOOKS_DIR", str(PROJECT_ROOT / "data" / "playbooks"))
).resolve()
REQUEST_TIMEOUT = 90.0


@st.cache_resource(show_spinner=False)
def ensure_embedded_backend() -> bool:
    """Start FastAPI in a background thread when running standalone (e.g. Streamlit Cloud)."""
    try:
        resp = httpx.get(f"{API_BASE_URL}/health", timeout=2.0)
        if resp.status_code == 200:
            return True
    except Exception:
        pass

    if not ("127.0.0.1" in API_BASE_URL or "localhost" in API_BASE_URL):
        return False

    import uvicorn
    from app.main import app as fastapi_app

    def _run_server() -> None:
        config = uvicorn.Config(
            fastapi_app,
            host="127.0.0.1",
            port=8000,
            log_level="warning",
        )
        uvicorn.Server(config).run()

    thread = threading.Thread(target=_run_server, daemon=True)
    thread.start()

    for _ in range(30):
        try:
            resp = httpx.get(f"{API_BASE_URL}/health", timeout=1.5)
            if resp.status_code == 200:
                return True
        except Exception:
            time.sleep(0.5)
    return False


SEVERITY_STYLES: dict[str, tuple[str, str, str]] = {
    "Critical": ("#B91C1C", "#FEE2E2", "#FCA5A5"),
    "High": ("#C2410C", "#FFEDD5", "#FDBA74"),
    "Medium": ("#A16207", "#FEF9C3", "#FDE047"),
    "Low": ("#0F766E", "#CCFBF1", "#5EEAD4"),
}

STATUS_STYLES: dict[str, tuple[str, str, str]] = {
    "Open": ("#1D4ED8", "#DBEAFE", "#93C5FD"),
    "Resolved": ("#0F766E", "#CCFBF1", "#5EEAD4"),
    "False Positive": ("#475569", "#E2E8F0", "#CBD5E1"),
}

ensure_embedded_backend()

# ---------------------------------------------------------------------------
# Light-Mode Cybersecurity Ops Design System
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

        html, body, .stApp, p, span, div, label, input, textarea, select, button {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
        }
        h1, h2, h3, h4, .topbar-title, .section-title, .sidebar-brand {
            font-family: 'Space Grotesk', sans-serif !important;
        }
        code, pre, .mono, .mitre-tag, .model-tag, .fp-tag, .env-tag,
        div[data-testid="stMetricValue"] {
            font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, monospace !important;
        }

        #MainMenu, footer, [data-testid="stDeployButton"] { display: none !important; visibility: hidden; }
        header[data-testid="stHeader"] { background: transparent; }
        .stApp { background-color: #F4F6FA; color: #0F172A; }

        [data-testid="stSidebar"] {
            background-color: #0F172A;
            border-right: 2px solid #0D9488;
        }
        [data-testid="stSidebar"] * { color: #E2E8F0 !important; }
        [data-testid="stSidebar"] hr { border-color: #1E293B !important; }
        [data-testid="stSidebar"] .stButton > button {
            background-color: #1E293B !important;
            color: #F8FAFC !important;
            border: 1px solid #334155 !important;
        }
        [data-testid="stSidebar"] .stButton > button:hover {
            border-color: #14B8A6 !important;
            color: #5EEAD4 !important;
        }

        .block-container { padding-top: 1.35rem; padding-bottom: 2.5rem; max-width: 1340px; }

        .topbar {
            display: flex; align-items: center; justify-content: space-between;
            background-color: #FFFFFF; border: 1px solid #DCE3EE;
            border-left: 4px solid #0D9488; border-radius: 8px;
            padding: 14px 20px; margin-bottom: 18px;
        }
        .topbar-title { font-size: 1.38rem; font-weight: 700; color: #0F172A; letter-spacing: -0.02em; }
        .topbar-sub { font-size: 0.83rem; color: #475569; margin-left: 12px; font-weight: 500; }
        .env-tag {
            font-size: 0.72rem; font-weight: 600; color: #0F766E;
            background-color: #CCFBF1; border: 1px solid #5EEAD4;
            padding: 4px 10px; border-radius: 5px; letter-spacing: 0.05em;
        }

        div[data-testid="stMetric"] {
            background-color: #FFFFFF; border: 1px solid #DCE3EE;
            border-top: 3px solid #0D9488; border-radius: 8px; padding: 15px 18px;
        }
        div[data-testid="stHorizontalBlock"] > div:nth-child(1) div[data-testid="stMetric"] { border-top-color: #2563EB; }
        div[data-testid="stHorizontalBlock"] > div:nth-child(2) div[data-testid="stMetric"] { border-top-color: #DC2626; }
        div[data-testid="stHorizontalBlock"] > div:nth-child(3) div[data-testid="stMetric"] { border-top-color: #D97706; }
        div[data-testid="stHorizontalBlock"] > div:nth-child(4) div[data-testid="stMetric"] { border-top-color: #0D9488; }
        div[data-testid="stMetric"] label {
            color: #475569 !important; font-size: 0.73rem !important; font-weight: 600 !important;
            text-transform: uppercase; letter-spacing: 0.06em;
        }
        div[data-testid="stMetricValue"] { color: #0F172A !important; font-weight: 600 !important; font-size: 1.55rem !important; }

        .section-title {
            font-size: 1.02rem; font-weight: 700; color: #0F172A;
            border-left: 3px solid #2563EB; padding-left: 10px; margin: 20px 0 12px 0;
        }
        .sidebar-brand { font-size: 1.05rem; font-weight: 700; letter-spacing: 0.08em; color: #5EEAD4 !important; margin-bottom: 2px; }
        .sidebar-sub { font-size: 0.72rem; color: #94A3B8 !important; margin-bottom: 14px; letter-spacing: 0.04em; }
        .sidebar-label { font-size: 0.69rem; font-weight: 600; letter-spacing: 0.09em; color: #94A3B8 !important; text-transform: uppercase; margin-bottom: 6px; }
        .status-row { display: flex; align-items: center; justify-content: space-between; font-size: 0.79rem; padding: 6px 0; border-bottom: 1px solid #1E293B; }
        .status-row:last-child { border-bottom: none; }
        .state-ok { font-family: 'IBM Plex Mono', monospace !important; font-size: 0.70rem; font-weight: 600; color: #2DD4BF !important; background: rgba(20, 184, 166, 0.14); padding: 2px 6px; border-radius: 4px; }
        .state-warn { font-family: 'IBM Plex Mono', monospace !important; font-size: 0.70rem; font-weight: 600; color: #FBBF24 !important; background: rgba(245, 158, 11, 0.15); padding: 2px 6px; border-radius: 4px; }
        .state-err { font-family: 'IBM Plex Mono', monospace !important; font-size: 0.70rem; font-weight: 600; color: #F87171 !important; background: rgba(239, 68, 68, 0.15); padding: 2px 6px; border-radius: 4px; }

        .badge { display: inline-block; padding: 3px 9px; border-radius: 5px; font-size: 0.73rem; font-weight: 700; margin-right: 6px; }
        .mitre-tag { display: inline-block; padding: 3px 9px; border-radius: 5px; background-color: #EEF2FF; border: 1px solid #C7D2FE; color: #3730A3; font-size: 0.73rem; font-weight: 600; margin-right: 6px; }
        .model-tag { display: inline-block; padding: 3px 9px; border-radius: 5px; background-color: #F0FDFA; border: 1px solid #99F6E4; color: #0F766E; font-size: 0.73rem; font-weight: 600; margin-right: 6px; }
        .fp-tag { display: inline-block; padding: 3px 9px; border-radius: 5px; background-color: #FFFBEB; border: 1px solid #FDE68A; color: #92400E; font-size: 0.73rem; font-weight: 600; margin-right: 6px; }

        .story-panel { background-color: #F8FAFC; border: 1px solid #DCE3EE; border-left: 4px solid #2563EB; border-radius: 6px; padding: 13px 16px; margin: 10px 0 14px 0; color: #0F172A; font-size: 0.90rem; line-height: 1.6; }
        .policy-bar { background-color: #F0FDFA; border: 1px solid #99F6E4; border-left: 4px solid #0D9488; border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; font-size: 0.83rem; color: #134E4A; }
        div[data-testid="stChatMessage"] { background-color: #FFFFFF; border: 1px solid #DCE3EE; border-left: 3px solid #0D9488; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
        div[data-testid="stExpander"] { background-color: #FFFFFF; border: 1px solid #DCE3EE; border-radius: 8px; margin-bottom: 10px; }
        .stButton > button { border-radius: 6px !important; font-weight: 600 !important; font-size: 0.83rem !important; padding: 0.45rem 0.95rem !important; }
        button[data-baseweb="tab"] { font-size: 0.84rem !important; font-weight: 600 !important; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# FastAPI HTTP Client Helpers
# ---------------------------------------------------------------------------
def api_get(path: str, params: dict[str, Any] | None = None) -> tuple[Any | None, str | None]:
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"{API_BASE_URL}{path}", params=params)
            resp.raise_for_status()
            return resp.json(), None
    except Exception as exc:
        return None, str(exc)


def api_post_ingest(
    raw_logs: str,
    source_type: str = "auto",
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{API_BASE_URL}/ingest",
                json={"raw_logs": raw_logs, "source_type": source_type},
            )
            if resp.status_code >= 400:
                detail = resp.json().get("detail", resp.text)
                return None, f"HTTP {resp.status_code}: {detail}"
            return resp.json(), None
    except Exception as exc:
        return None, str(exc)


def api_post_chat(
    message: str,
    incident_id: str | None,
    history: list[dict[str, str]],
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
            resp = client.post(
                f"{API_BASE_URL}/chat",
                json={"message": message, "incident_id": incident_id, "history": history},
            )
            if resp.status_code >= 400:
                detail = resp.json().get("detail", resp.text)
                return None, f"HTTP {resp.status_code}: {detail}"
            return resp.json(), None
    except Exception as exc:
        return None, str(exc)


def api_update_status(incident_id: str, new_status: str) -> tuple[bool, str | None]:
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.patch(
                f"{API_BASE_URL}/incidents/{incident_id}/status",
                json={"status": new_status},
            )
            resp.raise_for_status()
            return True, None
    except Exception as exc:
        return False, str(exc)


def load_sample_file(filename: str) -> str:
    target = SAMPLE_LOGS_DIR / filename
    return target.read_text(encoding="utf-8") if target.exists() else ""


# ---------------------------------------------------------------------------
# UI Components
# ---------------------------------------------------------------------------
def _status_line(label: str, state: str, text: str) -> str:
    cls = {"ok": "state-ok", "warn": "state-warn", "err": "state-err"}.get(state, "state-warn")
    return f'<div class="status-row"><span>{label}</span><span class="{cls}">{text}</span></div>'


def render_sidebar() -> str:
    with st.sidebar:
        st.markdown('<div class="sidebar-brand">SOC COMMAND</div>', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-sub">DEFENSIVE OPERATIONS</div>', unsafe_allow_html=True)
        nav = st.radio(
            "Navigation",
            options=["Triage & Incidents", "Analyst Chat", "Playbooks & Health"],
            index=0,
            label_visibility="collapsed",
        )

        st.divider()
        health, err = api_get("/health")
        if err or not health:
            st.markdown(_status_line("Engine Status", "err", "OFFLINE"), unsafe_allow_html=True)
        elif health.get("database_connected") and health.get("gemini_configured"):
            st.markdown(_status_line("Engine Status", "ok", "ONLINE"), unsafe_allow_html=True)
        else:
            st.markdown(_status_line("Engine Status", "warn", "DEGRADED"), unsafe_allow_html=True)

    return nav


def render_kpi_row() -> None:
    stats, err = api_get("/stats")
    if err or not stats:
        st.warning("Unable to load telemetry from backend API.")
        return

    c1, c2, c3, c4 = st.columns(4)
    c1.metric(
        label="Batches Analyzed",
        value=int(stats.get("total_batches_analyzed", 0)),
        delta=f"{stats.get('cached_iocs_count', 0)} IoCs cached",
    )
    c2.metric(
        label="Active Critical / High",
        value=int(stats.get("active_critical_high_incidents", 0)),
        delta=f"{stats.get('incidents_by_status', {}).get('Open', 0)} open total",
        delta_color="inverse",
    )
    c3.metric(
        label="Mean False-Positive Rate",
        value=f"{stats.get('mean_false_positive_rate', 0.0):.1f}%",
    )
    c4.metric(
        label="TI Cache Hit Rate",
        value=f"{stats.get('cache_hit_rate', 0.0):.1f}%",
        delta=f"{stats.get('total_cache_hits', 0)} API calls saved",
    )


def _execute_ingestion(raw_logs: str, source_type: str, label: str) -> None:
    if not raw_logs.strip():
        st.warning("Provide log lines or upload a file before running analysis.")
        return

    with st.spinner(f"Analyzing {label}..."):
        result, err = api_post_ingest(raw_logs=raw_logs, source_type=source_type)

    if err or not result:
        st.error(f"Ingestion failed: {err}")
        return

    st.session_state["last_ingest_result"] = {"label": label, "result": result}
    st.rerun()


def render_ingestion_panel(show_inline_output: bool = False) -> None:
    st.markdown('<div class="section-title">Log Ingestion</div>', unsafe_allow_html=True)

    d1, d2 = st.columns(2)
    with d1:
        if st.button(
            "Load Sample: SSH Brute Force & Sudo (auth.log)",
            type="secondary",
            use_container_width=True,
        ):
            _execute_ingestion(load_sample_file("auth.log"), "auth.log", "sample auth.log")
    with d2:
        if st.button(
            "Load Sample: Web Path Traversal & SQLi (access.log)",
            type="secondary",
            use_container_width=True,
        ):
            _execute_ingestion(load_sample_file("access.log"), "access.log", "sample access.log")

    tab_upload, tab_paste = st.tabs(["Upload File", "Paste Raw Logs"])

    with tab_upload:
        uploaded = st.file_uploader(
            "Select server log file (.log or .txt)",
            type=["log", "txt"],
            key="soc_log_uploader",
        )
        col_fmt, col_btn = st.columns([2, 1])
        with col_fmt:
            src_hint_up = st.selectbox(
                "Log Format",
                options=["auto", "auth.log", "access.log"],
                key="upload_source_hint",
                label_visibility="collapsed",
            )
        with col_btn:
            if st.button("Analyze File", type="primary", use_container_width=True):
                if uploaded is None:
                    st.warning("Upload a log file first.")
                else:
                    text = uploaded.read().decode("utf-8", errors="replace")
                    _execute_ingestion(text, src_hint_up, uploaded.name)

    with tab_paste:
        pasted = st.text_area(
            "Raw log lines",
            height=150,
            placeholder=(
                "Nov 24 14:21:05 prod-bastion sshd[4821]: Failed password for invalid user admin "
                "from 185.220.101.45 port 51234 ssh2"
            ),
            label_visibility="collapsed",
        )
        col_fmt2, col_btn2 = st.columns([2, 1])
        with col_fmt2:
            src_hint_paste = st.selectbox(
                "Log Format",
                options=["auto", "auth.log", "access.log"],
                key="paste_source_hint",
                label_visibility="collapsed",
            )
        with col_btn2:
            if st.button("Analyze Logs", type="primary", use_container_width=True):
                _execute_ingestion(pasted, src_hint_paste, "pasted logs")

    last_payload = st.session_state.get("last_ingest_result")
    if last_payload:
        res = last_payload["result"]
        label = last_payload["label"]
        replay_note = " (idempotent cache replay — 0 LLM tokens spent)" if res.get("idempotent_replay") else ""
        c_msg, c_clr = st.columns([5, 1])
        with c_msg:
            st.success(
                f"Analysis complete ({label}){replay_note} — {res['total_lines']} lines processed, "
                f"{res['benign_discarded']} benign discarded, {res['suspicious_events']} suspicious "
                f"events across {res['batches_created']} batch(es), "
                f"{len(res['incidents'])} incident(s)."
            )
        with c_clr:
            if st.button("Clear Output", key="clear_last_ingest", use_container_width=True):
                st.session_state.pop("last_ingest_result", None)
                st.rerun()

        if show_inline_output:
            created_incidents = res.get("incidents") or []
            if created_incidents:
                st.markdown(
                    '<div class="section-title">Latest Analysis Output</div>',
                    unsafe_allow_html=True,
                )
                live_list, _ = api_get("/incidents")
                live_by_id = {item["id"]: item for item in (live_list or [])}
                for inc in created_incidents:
                    fresh_inc = live_by_id.get(inc["id"], inc)
                    render_incident_card(fresh_inc, key_prefix="ingest_", force_expand=True)
            else:
                st.info("No suspicious activity detected in this file.")


def render_incident_card(
    inc: dict[str, Any],
    key_prefix: str = "",
    force_expand: bool = False,
) -> None:
    severity = inc.get("severity", "Medium")
    status_val = inc.get("status", "Open")
    sev_fg, sev_bg, sev_border = SEVERITY_STYLES.get(severity, ("#475569", "#E2E8F0", "#CBD5E1"))
    st_fg, st_bg, st_border = STATUS_STYLES.get(status_val, ("#475569", "#E2E8F0", "#CBD5E1"))

    mitre_id = inc.get("mitre_attack_id", "Unknown")
    technique = inc.get("technique_name", "Suspicious Activity")
    confidence = float(inc.get("confidence_score", 0.0)) * 100.0
    fp_prob = float(inc.get("false_positive_probability", 0.0)) * 100.0
    created_short = str(inc.get("created_at", ""))[:19].replace("T", " ")

    time_short = created_short[11:16] if len(created_short) >= 16 else created_short
    header = f"{mitre_id} — {technique}  ·  {time_short} UTC"
    expanded_default = force_expand or (severity in ("Critical", "High") and status_val == "Open")

    with st.expander(header, expanded=expanded_default):
        otx_tag = (
            '<span class="badge" style="color:#6D28D9;background:#EDE9FE;border:1px solid #C4B5FD;">'
            "OTX Correlated</span>"
            if inc.get("otx_queried")
            else ""
        )
        st.markdown(
            f"""
            <div style="margin-bottom:10px;">
                <span class="badge" style="color:{sev_fg};background:{sev_bg};border:1px solid {sev_border};">
                    {severity.upper()}
                </span>
                <span class="badge" style="color:{st_fg};background:{st_bg};border:1px solid {st_border};">
                    {status_val}
                </span>
                <span class="mitre-tag">Conf {confidence:.0f}%</span>
                <span class="fp-tag">FP {fp_prob:.0f}%</span>
                {otx_tag}
            </div>
            """,
            unsafe_allow_html=True,
        )

        tab_summary, tab_ioc, tab_remediation, tab_audit = st.tabs(
            ["Summary & Disposition", "IoC Enrichment", "Playbook & Containment", "Audit & Evidence"]
        )

        with tab_summary:
            st.markdown(
                f'<div class="story-panel">{inc.get("attack_story", "")}</div>',
                unsafe_allow_html=True,
            )
            b1, b2, b3 = st.columns([1, 1, 2])
            inc_id = inc["id"]
            with b1:
                if st.button(
                    "Mark Resolved",
                    key=f"{key_prefix}resolve_{inc_id}",
                    disabled=(status_val == "Resolved"),
                    use_container_width=True,
                ):
                    ok, err = api_update_status(inc_id, "Resolved")
                    if ok:
                        st.rerun()
                    else:
                        st.error(f"Update failed: {err}")
            with b2:
                if st.button(
                    "Mark False Positive",
                    key=f"{key_prefix}fp_{inc_id}",
                    disabled=(status_val == "False Positive"),
                    use_container_width=True,
                ):
                    ok, err = api_update_status(inc_id, "False Positive")
                    if ok:
                        st.rerun()
                    else:
                        st.error(f"Update failed: {err}")
            with b3:
                if status_val != "Open" and st.button(
                    "Reopen Incident",
                    key=f"{key_prefix}reopen_{inc_id}",
                    use_container_width=True,
                ):
                    ok, err = api_update_status(inc_id, "Open")
                    if ok:
                        st.rerun()
                    else:
                        st.error(f"Update failed: {err}")

        with tab_ioc:
            iocs = inc.get("ioc_enrichment") or []
            if iocs:
                rows = []
                for item in iocs:
                    country = item.get("country_name") or item.get("country_code") or "Unknown"
                    isp = item.get("isp") or "Unknown"
                    rows.append(
                        {
                            "Source IP": item.get("ip_address", ""),
                            "Country / ISP": f"{country} ({isp})",
                            "AbuseIPDB": f"{item.get('abuse_confidence_score', 0)}/100",
                            "Tor": "Yes" if item.get("is_tor") else "No",
                            "OTX Pulses": int(item.get("otx_pulse_count", 0))
                            if item.get("otx_checked")
                            else "Not Queried",
                            "Cache": item.get("cache_status", "MISS"),
                        }
                    )
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("No public external IP indicators extracted in this batch.")

        with tab_remediation:
            st.markdown(
                f"""
                <div class="policy-bar">
                    <strong>Playbook Reference:</strong> <code>{inc.get('playbook_reference', 'N/A')}</code><br/>
                    Containment commands are validated against shell injection and provided for human analyst review only.
                </div>
                """,
                unsafe_allow_html=True,
            )
            commands = inc.get("remediation_commands") or []
            if commands:
                for cmd in commands:
                    st.code(cmd, language="bash")
            else:
                st.caption("No containment commands recommended for this event.")

        with tab_audit:
            a1, a2, a3, a4 = st.columns(4)
            tokens = inc.get("token_usage") or {}
            a1.metric("Model", inc.get("model_used", "gemini-3.5-flash-lite"))
            a2.metric("Latency", f"{int(inc.get('latency_ms', 0))} ms")
            a3.metric("Total Tokens", int(tokens.get("total_tokens", 0)))
            a4.metric("Prompt Version", inc.get("prompt_version", "v2.0"))
            st.caption(f"Routing Decision: `{inc.get('routing_reason', 'rapid_triage')}`")
            st.json(inc.get("evidence") or {})


def render_incident_feed() -> None:
    st.markdown('<div class="section-title">Incident Queue</div>', unsafe_allow_html=True)

    f1, f2 = st.columns(2)
    with f1:
        severity_filter = st.selectbox(
            "Severity",
            options=["All", "Critical", "High", "Medium", "Low"],
            index=0,
        )
    with f2:
        status_filter = st.selectbox(
            "Status",
            options=["All", "Open", "False Positive", "Resolved"],
            index=0,
        )

    params: dict[str, Any] = {}
    if severity_filter != "All":
        params["severity"] = severity_filter
    if status_filter != "All":
        params["status"] = status_filter

    incidents, err = api_get("/incidents", params=params)
    if err:
        st.error(f"Could not load incidents: {err}")
        return

    if not incidents:
        st.info("No incidents match the selected filters.")
        return

    for inc in incidents:
        render_incident_card(inc, key_prefix="feed_")


def render_analyst_chat() -> None:
    st.markdown('<div class="section-title">Analyst Chat</div>', unsafe_allow_html=True)

    if "soc_chat_messages" not in st.session_state:
        st.session_state.soc_chat_messages = []

    incidents, _ = api_get("/incidents")
    incident_options: dict[str, str | None] = {"All Recent Incidents & Logs": None}
    for inc in incidents or []:
        label = (
            f"{inc.get('severity', '').upper()} — {inc.get('mitre_attack_id')} "
            f"{inc.get('technique_name')} ({str(inc.get('created_at', ''))[:16].replace('T', ' ')})"
        )
        incident_options[label] = inc["id"]

    c_scope, c_clear = st.columns([4, 1])
    with c_scope:
        selected_label = st.selectbox(
            "Investigation Scope",
            options=list(incident_options.keys()),
            index=0,
        )
        scoped_id = incident_options[selected_label]
    with c_clear:
        st.write("")
        st.write("")
        if st.button("Clear Chat", use_container_width=True):
            st.session_state.soc_chat_messages = []
            st.rerun()

    if not st.session_state.soc_chat_messages:
        st.caption("Suggested questions (Arabic or English):")
        q1, q2, q3 = st.columns(3)
        starter_prompt: str | None = None
        with q1:
            if st.button("Summarize what happened in the latest log file", use_container_width=True):
                starter_prompt = (
                    "Summarize what happened in the latest uploaded log file, "
                    "including source IPs, targeted accounts, and severity."
                )
        with q2:
            if st.button("Which IP is most dangerous and why?", use_container_width=True):
                starter_prompt = (
                    "Which source IP in the logs is the most dangerous based on the "
                    "raw events and Threat Intel, and what should I block first?"
                )
        with q3:
            if st.button("Explain the containment commands step by step", use_container_width=True):
                starter_prompt = (
                    "Explain each recommended containment command step by step and "
                    "note any operational precautions before running it."
                )

        if starter_prompt:
            _send_chat_message(starter_prompt, scoped_id)
            st.rerun()

    for msg in st.session_state.soc_chat_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_input = st.chat_input(
        "Ask about any IP, user, log line, or remediation step (Arabic or English)..."
    )
    if user_input:
        _send_chat_message(user_input, scoped_id)
        st.rerun()


def _send_chat_message(prompt: str, incident_id: str | None) -> None:
    history = [
        {"role": m["role"], "content": m["content"]}
        for m in st.session_state.soc_chat_messages[-8:]
    ]
    st.session_state.soc_chat_messages.append({"role": "user", "content": prompt})

    with st.spinner("Analyzing logs and incidents..."):
        resp, err = api_post_chat(message=prompt, incident_id=incident_id, history=history)

    if err or not resp:
        st.session_state.soc_chat_messages.append(
            {"role": "assistant", "content": f"Error contacting SOC Copilot: {err}"}
        )
    else:
        st.session_state.soc_chat_messages.append(
            {"role": "assistant", "content": resp["reply"]}
        )


def render_playbooks_and_health() -> None:
    st.markdown('<div class="section-title">Indexed SOC Playbooks</div>', unsafe_allow_html=True)
    if PLAYBOOKS_DIR.exists():
        for md_path in sorted(PLAYBOOKS_DIR.glob("*.md")):
            with st.expander(md_path.name, expanded=False):
                st.markdown(md_path.read_text(encoding="utf-8"))
    else:
        st.warning(f"Playbooks directory not found: {PLAYBOOKS_DIR}")

    st.markdown('<div class="section-title">System Diagnostics</div>', unsafe_allow_html=True)
    health, err = api_get("/health")
    if err:
        st.error(f"Health endpoint unreachable: {err}")
    else:
        h1, h2, h3, h4 = st.columns(4)
        h1.metric("Postgres + pgvector", "Online" if health.get("database_connected") else "Down")
        h2.metric("Gemini API", "Ready" if health.get("gemini_configured") else "Unset")
        h3.metric("Threat Intel Feeds", "Active" if health.get("abuseipdb_configured") else "Partial")
        h4.metric("Playbook Chunks", int(health.get("playbooks_indexed", 0)))
        with st.expander("Raw Health Payload", expanded=False):
            st.json(health)


def main() -> None:
    selected_view = render_sidebar()

    st.markdown(
        """
        <div class="topbar">
            <div>
                <span class="topbar-title">SOC Triage Console</span>
                <span class="topbar-sub">Defensive Threat Analysis &amp; Response</span>
            </div>
            <span class="env-tag">DEFENSIVE OPS · HITL</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    render_kpi_row()

    if selected_view == "Triage & Incidents":
        render_ingestion_panel(show_inline_output=False)
        render_incident_feed()
    elif selected_view == "Analyst Chat":
        render_analyst_chat()
    else:
        render_playbooks_and_health()


if __name__ == "__main__":
    main()