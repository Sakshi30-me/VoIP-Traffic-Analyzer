# voip traffic analyzer
import streamlit as st
import pandas as pd
import numpy as np
import os
import io
from scapy.all import rdpcap, UDP, IP
from datetime import datetime
import matplotlib.pyplot as plt

# Plotly for interactive visualizations
import plotly.graph_objects as go
import plotly.express as px

# ---------------------------
# PAGE CONFIG & THEME
# ---------------------------
st.set_page_config(page_title="VoIP TRACKER", layout="wide", page_icon="📞")


shodan_css = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@300;400;500;700&display=swap');

html, body, [class*="css"]  {
    font-family: 'Roboto Mono', monospace;
    background-color: #0A0A0A !important;
    color: #E5E5E5;
}

/* --- HERO TITLE --- */
.big-title {
    font-size: 60px;
    font-weight: 700;
    color: #013220;
    text-align: left;
    margin-top: 8px;
    text-shadow: 0 0 12px #006400;
}

/* --- SUBTITLE --- */
.sub-title {
    font-size: 14px;
    color: #C8C8C8;
    text-align: left;
    margin-bottom: 18px;
}

/* --- NEON CARD --- */
.neon-card {
    background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
    padding: 18px;
    border-radius: 12px;
    border: 1px solid rgba(0,255,65,0.12);
    box-shadow: 0 0 12px rgba(0,255,65,0.04);
    transition: 0.25s ease;
}
.neon-card:hover {
    transform: scale(1.01);
    box-shadow: 0 0 30px rgba(0,255,65,0.12);
}

/* --- NEON BUTTON --- */
.stButton>button {
    background: linear-gradient(90deg, #07140A, #07140A) !important;
    border: 1px solid #00FF41 !important;
    color: #00FF41 !important;
    padding: 10px 18px;
    border-radius: 8px;
    font-size: 15px;
    transition: 0.25s ease;
}
.stButton>button:hover {
    box-shadow: 0px 0px 18px #013220;
    transform: translateY(-2px);
}

/* --- FILE UPLOADER --- */
.stFileUploader>div>div {
    background-color: #0F0F0F !important;
    border: 1px dashed rgba(0,255,65,0.14) !important;
    color: #013220 !important;
    border-radius: 8px;
}

/* small muted text */
.small-muted { color: #9aa0a6; font-size:13px; }

hr {
    border: 0;
    height: 1px;
    background: linear-gradient(90deg, rgba(0,255,65,0.15), rgba(0,255,65,0.05));
    margin: 18px 0;
}
</style>
"""
st.markdown(shodan_css, unsafe_allow_html=True)

# ---------------------------
# HEADER
# ---------------------------
col1, col2 = st.columns([0.15, 0.85])
with col1:
    st.markdown("<div style='font-size:38px'>📞</div>", unsafe_allow_html=True)
with col2:
    st.markdown("<div class='big-title'>VoIP TRACKER</div>", unsafe_allow_html=True)
    st.markdown("<div class='sub-title'>Stop Guessing, Start Optimizing: Real-Time Voice Monitoring.</div>", unsafe_allow_html=True)

st.markdown("<hr>", unsafe_allow_html=True)

# ---------------------------
# HELPER FUNCTIONS 
# ---------------------------
def parse_sip_payload(payload_bytes):
    """Decode payload bytes and extract simple SIP fields + SDP audio info (connection IP and audio ports)."""
    try:
        text = payload_bytes.decode(errors="ignore")
    except:
        return None
    if not any(k in text for k in ["INVITE", "BYE", "SIP/2.0", "200 OK", "ACK"]):
        return None
    res = {}
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for l in lines:
        low = l.lower()
        if low.startswith("call-id:"):
            res["call_id"] = l.split(":",1)[1].strip()
        if low.startswith("from:"):
            res["from"] = l.split(":",1)[1].strip()
        if low.startswith("to:"):
            res["to"] = l.split(":",1)[1].strip()
        if l.startswith("INVITE") or l.startswith("BYE") or "200 OK" in l or l.startswith("ACK"):
            res["sip_start_line"] = l
    # SDP body detection
    sdp_text = ""
    if "\r\n\r\n" in text:
        sdp_text = text.split("\r\n\r\n",1)[1]
    elif "\n\n" in text:
        sdp_text = text.split("\n\n",1)[1]
    # parse connection line and audio m= lines
    for l in sdp_text.splitlines():
        l = l.strip()
        if l.startswith("c=") and "IN IP4" in l:
            try:
                ip = l.split()[-1].strip()
                res["sdp_connection"] = ip
            except:
                pass
        if l.startswith("m=") and "audio" in l:
            parts = l.split()
            if len(parts) >= 2:
                try:
                    res.setdefault("audio_ports", []).append(int(parts[1]))
                except:
                    pass
    return res if res else None

def is_rtp_like(udp_payload):
    """Heuristic: payload at least 12 bytes and RTP version == 2 (top two bits == 10)."""
    if not udp_payload or len(udp_payload) < 12:
        return False
    first = udp_payload[0]
    if (first & 0xC0) >> 6 == 2:
        return True
    return False

def rtp_seq_from_payload(payload):
    if len(payload) >= 4:
        return (payload[2] << 8) | payload[3]
    return None

def rtp_timestamp_from_payload(payload):
    if len(payload) >= 8:
        return (payload[4]<<24)|(payload[5]<<16)|(payload[6]<<8)|payload[7]
    return None

# ---------------------------
# Original analyze_pcaps (kept exactly as you provided)
# ---------------------------
def analyze_pcaps(pcap_paths):
    """
    pcap_paths: list of file paths to .pcap/.pcapng files
    returns: results_list (per call), csv_df (flat table)
    """
    sip_sessions = {}
    rtp_flows = {}

    # Read packets from all pcaps (concatenate)
    packets = []
    for p in pcap_paths:
        if not os.path.isfile(p):
            continue
        try:
            pkts = rdpcap(p)
            packets.extend(pkts)
        except Exception as e:
            st.warning(f"Failed to read {p}: {e}")

    # iterate packets
    for pkt in packets:
        try:
            ts = datetime.fromtimestamp(float(pkt.time))
        except:
            ts = None
        # Extract raw payload bytes for SIP detection
        try:
            raw = bytes(pkt.payload.payload)
        except Exception:
            raw = b""
        sipinfo = parse_sip_payload(raw)
        if sipinfo:
            callid = sipinfo.get("call_id") or f"call_{len(sip_sessions)+1}"
            rec = sip_sessions.get(callid, {})
            start_line = sipinfo.get("sip_start_line","")
            if "INVITE" in start_line and not rec.get("start_time"):
                rec["start_time"] = ts
            if "BYE" in start_line and not rec.get("end_time"):
                rec["end_time"] = ts
            if ("200 OK" in start_line or "OK" in start_line) and not rec.get("connected_time"):
                rec["connected_time"] = ts
            rec.setdefault("from", sipinfo.get("from"))
            rec.setdefault("to", sipinfo.get("to"))
            if sipinfo.get("sdp_connection"):
                rec["sdp_connection"] = sipinfo.get("sdp_connection")
            if sipinfo.get("audio_ports"):
                rec.setdefault("audio_ports", []).extend(sipinfo.get("audio_ports"))
            sip_sessions[callid] = rec

        # RTP detection from UDP layer
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            try:
                ip_layer = pkt[IP]
                udp_layer = pkt[UDP]
                udp_payload = bytes(udp_layer.payload)
            except Exception:
                continue
            if is_rtp_like(udp_payload):
                key = (ip_layer.src, ip_layer.dst, udp_layer.sport, udp_layer.dport)
                meta = {
                    "time": ts,
                    "seq": rtp_seq_from_payload(udp_payload),
                    "timestamp": rtp_timestamp_from_payload(udp_payload),
                    "len": len(udp_payload)
                }
                rtp_flows.setdefault(key, []).append(meta)

    # correlate SIP -> RTP flows
    results = []
    for callid, rec in sip_sessions.items():
        audio_ports = set(rec.get("audio_ports", []))
        sdp_ip = rec.get("sdp_connection", None)
        matched_flows = []
        for (src, dst, sport, dport), pktlist in rtp_flows.items():
            if audio_ports and (sport in audio_ports or dport in audio_ports):
                if sdp_ip:
                    if sdp_ip in (src, dst):
                        matched_flows.append(((src, dst, sport, dport), pktlist))
                else:
                    matched_flows.append(((src, dst, sport, dport), pktlist))
        total_rtp_packets = sum(len(pktlist) for _, pktlist in matched_flows)
        start_time = rec.get("start_time")
        end_time = rec.get("end_time") or rec.get("connected_time")
        duration = None
        if start_time and end_time:
            duration = (end_time - start_time).total_seconds()
        flow_summaries = []
        for key, pktlist in matched_flows:
            seqs = [p["seq"] for p in pktlist if p["seq"] is not None]
            times = [p["time"] for p in pktlist if p["time"] is not None]
            count = len(seqs)
            packet_loss = 0.0
            jitter = None
            if seqs:
                expected = (max(seqs) - min(seqs) + 1) if max(seqs) >= min(seqs) else count
                if expected > count:
                    packet_loss = (expected - count) / expected * 100.0
                if len(times) >= 2:
                    intervals = [ (times[i] - times[i-1]).total_seconds()*1000.0 for i in range(1, len(times)) ]
                    if intervals:
                        jitter = float(np.std(intervals))
            flow_summaries.append({
                "flow": key,
                "packets": count,
                "packet_loss_pct": round(packet_loss,3),
                "jitter_ms": round(jitter,3) if jitter is not None else None
            })
        results.append({
            "call_id": callid,
            "from": rec.get("from"),
            "to": rec.get("to"),
            "start_time": rec.get("start_time"),
            "end_time": rec.get("end_time"),
            "duration_s": duration,
            "total_rtp_packets": total_rtp_packets,
            "rtp_flow_summaries": flow_summaries
        })

    # build flat CSV DataFrame
    csv_rows = []
    for r in results:
        base = {
            "call_id": r["call_id"],
            "from": r["from"],
            "to": r["to"],
            "start_time": r["start_time"],
            "end_time": r["end_time"],
            "duration_s": r["duration_s"],
            "total_rtp_packets": r["total_rtp_packets"]
        }
        if r["rtp_flow_summaries"]:
            for f in r["rtp_flow_summaries"]:
                src, dst, sport, dport = f["flow"]
                row = base.copy()
                row.update({
                    "flow_src": src, "flow_dst": dst, "flow_src_port": sport, "flow_dst_port": dport,
                    "flow_packets": f["packets"], "flow_packet_loss_pct": f["packet_loss_pct"],
                    "flow_jitter_ms": f["jitter_ms"]
                })
                csv_rows.append(row)
        else:
            csv_rows.append(base)
    csv_df = pd.DataFrame(csv_rows)
    return results, csv_df

# ---------------------------
# Visualization helpers (Plotly)
# ---------------------------
ACCENT = "#00FF41"
GOOD = "#2ECC71"
WARN = "#F39C12"
BAD  = "#E74C3C"
BG   = "#0A0A0A"

def plot_rtp_waveform(pkt_list, title="RTP Waveform (payload size vs time)"):
    if not pkt_list:
        return None
    df = pd.DataFrame(pkt_list)
    df = df.sort_values("time").reset_index(drop=True)
    df["tsec"] = (df["time"] - df["time"].iloc[0]).dt.total_seconds()
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["tsec"], y=df["len"], mode="lines+markers",
        line=dict(color=ACCENT), marker=dict(size=6),
        hovertemplate="t: %{x:.3f}s<br>len: %{y} bytes<br>seq: %{customdata}",
        customdata=df["seq"]
    ))
    fig.update_layout(
        title=title,
        xaxis_title="Time (s)",
        yaxis_title="Payload length (bytes)",
        template="plotly_dark",
        plot_bgcolor=BG, paper_bgcolor=BG,
        height=350
    )
    return fig

def plot_seq_time_and_gaps(pkt_list, title="Seq vs Time (gaps = packet loss)"):
    if not pkt_list:
        return None
    df = pd.DataFrame(pkt_list).sort_values("time").reset_index(drop=True)
    df["tsec"] = (df["time"] - df["time"].iloc[0]).dt.total_seconds()
    seqs = df["seq"].astype('float')
    df["seq_diff"] = seqs.diff().fillna(0)
    gap_df = df[df["seq_diff"] > 1]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["tsec"], y=df["seq"], mode="markers+lines",
        line=dict(color="#58A6FF"), marker=dict(size=6),
        name="seq"
    ))
    if not gap_df.empty:
        fig.add_trace(go.Scatter(
            x=gap_df["tsec"], y=gap_df["seq"], mode="markers",
            marker=dict(color=BAD, size=10, symbol="x"),
            name="Missing packets (gaps)",
            hovertemplate="t: %{x:.3f}s<br>seq: %{y}<br>gap: %{customdata}",
            customdata=gap_df["seq_diff"]
        ))
    fig.update_layout(title=title, xaxis_title="Time (s)", yaxis_title="RTP Sequence", template="plotly_dark", plot_bgcolor=BG, paper_bgcolor=BG, height=350)
    return fig

def plot_jitter_time(pkt_list, window=5, title="Interarrival Jitter (ms)"):
    if not pkt_list:
        return None
    df = pd.DataFrame(pkt_list).sort_values("time").reset_index(drop=True)
    times = pd.to_datetime(df["time"])
    df["iat_ms"] = (times.diff().dt.total_seconds() * 1000).fillna(0)
    df["jitter_ms"] = df["iat_ms"].rolling(window=window, min_periods=1).std().fillna(0)
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=(df["time"] - df["time"].iloc[0]).dt.total_seconds(), y=df["jitter_ms"], mode="lines+markers", line=dict(color=ACCENT),
                             hovertemplate="t: %{x:.3f}s<br>jitter: %{y:.3f} ms"))
    fig.update_layout(title=title, xaxis_title="Time (s)", yaxis_title="Jitter (ms)", template="plotly_dark", plot_bgcolor=BG, paper_bgcolor=BG, height=300)
    return fig

def estimate_mos(jitter_ms, packet_loss_pct):
    j = min(jitter_ms, 100)
    l = min(packet_loss_pct, 10)
    score = 4.5 - (j / 50.0) - (l / 2.5)
    mos = max(1.0, min(4.5, score))
    return round(mos, 2)

def detect_voip_issues(jitter_ms, packet_loss_pct, packets):
    alerts = []

    if jitter_ms is not None and jitter_ms > 30:
        alerts.append(("HIGH", "🚨 High jitter detected — possible congestion, jitter attack, or unstable network"))

    if packet_loss_pct is not None and packet_loss_pct > 5:
        alerts.append(("MEDIUM", "⚠️ Packet loss detected — degraded call quality or possible DoS"))

    if packet_loss_pct is not None and packet_loss_pct > 15:
        alerts.append(("CRITICAL", "🔥 Severe packet loss — possible VoIP DoS attack"))

    if packets is not None and packets < 20:
        alerts.append(("LOW", "⚠️ Very low packet count — incomplete stream or suspicious traffic"))

    return alerts


def plot_mos_gauge(mos_score, title="Estimated MOS"):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=mos_score,
        gauge={
            'axis': {'range': [1, 4.5]},
            'bar': {'color': ACCENT},
            'steps': [
                {'range': [1, 2.5], 'color': BAD},
                {'range': [2.5, 3.5], 'color': WARN},
                {'range': [3.5, 4.5], 'color': GOOD}
            ],
        },
        number={'suffix': " MOS"}
    ))
    fig.update_layout(title=title, template="plotly_dark", plot_bgcolor=BG, paper_bgcolor=BG, height=300)
    return fig

# ---------------------------
# Helper to rebuild RTP packet lists (for visualization)
# ---------------------------
def build_rtp_flows_from_pcaps(pcap_paths):
    """
    Parse pcaps and return dict: (src,dst,sport,dport) -> list of pkt dicts with time, seq, timestamp, len
    """
    rtp_flows_local = {}
    packets = []
    for p in pcap_paths:
        if not os.path.isfile(p):
            continue
        try:
            pkts = rdpcap(p)
            packets.extend(pkts)
        except Exception:
            continue

    for pkt in packets:
        try:
            ts = datetime.fromtimestamp(float(pkt.time))
        except:
            ts = None
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            try:
                ip_layer = pkt[IP]
                udp_layer = pkt[UDP]
                udp_payload = bytes(udp_layer.payload)
            except Exception:
                continue
            if is_rtp_like(udp_payload):
                key = (ip_layer.src, ip_layer.dst, udp_layer.sport, udp_layer.dport)
                meta = {
                    "time": ts,
                    "seq": rtp_seq_from_payload(udp_payload),
                    "timestamp": rtp_timestamp_from_payload(udp_payload),
                    "len": len(udp_payload)
                }
                rtp_flows_local.setdefault(key, []).append(meta)
    # sort lists by time
    for k in list(rtp_flows_local.keys()):
        rtp_flows_local[k] = sorted(rtp_flows_local[k], key=lambda x: x.get("time") or datetime.min)
    return rtp_flows_local

# ---------------------------
# UI: Inputs & Running Analysis (keeps original layout & logic)
# ---------------------------
st.markdown("## UPLOAD THE TELEPHONY (SIP OR RTP PCAP)")
st.markdown("#### Open the Wireshark Capture and capture the audio stream and save it as a PCAP file. Upload the PCAP file here for analysis.")
os.makedirs("data", exist_ok=True)

server_pcaps = [f for f in os.listdir(r'...\Tracing-voip\data') if f.lower().endswith((".pcap", ".pcapng"))]
st.markdown(f"**Available network sniffs**: {', '.join(server_pcaps) if server_pcaps else 'No samples found'}")
st.markdown("----------------------------------------------------------------------------------------------------------------------------")
st.markdown("### Preview with Sample Data")
use_server = st.checkbox("Demo Analysis", value=False)

selected_paths = []
if use_server and server_pcaps:
    chosen = st.multiselect("Choose File(s)", server_pcaps, default=server_pcaps[:2])
    selected_paths = [os.path.join("data", s) for s in chosen]
else:
    uploaded = st.file_uploader("Upload up to 2 PCAP files", type=["pcap","pcapng"], accept_multiple_files=True)
    if uploaded:
        temp_paths = []
        for idx, up in enumerate(uploaded, start=1):
            fp = os.path.join("data", f"uploaded_{idx}.pcap")
            with open(fp, "wb") as fh:
                fh.write(up.read())
            temp_paths.append(fp)
        selected_paths = temp_paths

st.markdown("")  # spacer
if st.button("Run Analysis"):
    if not selected_paths:
        st.warning("No PCAPs provided. Upload files or select sample PCAPs from data/.")
    else:
        st.info(f"Analyzing: {selected_paths}")
        with st.spinner("Parsing pcaps and extracting SIP/RTP metadata..."):
            # run original analyzer (unchanged)
            results, csv_df = analyze_pcaps(selected_paths)

            # build rtp packet lists separately for visualization
            rtp_flows_for_vis = build_rtp_flows_from_pcaps(selected_paths)

        if not results:
            st.warning("No SIP sessions detected in the given PCAP(s). Try a different capture.")
        else:
            st.success(f"Found {len(results)} SIP session(s). Showing summary below.")

            # Top-level metrics container
            total_calls = len(results)
            total_rtp_packets = int(csv_df["total_rtp_packets"].sum()) if not csv_df.empty else 0
            avg_duration = round(np.nanmean([r["duration_s"] for r in results if r["duration_s"] is not None]),2) if results else 0

            mcol1, mcol2, mcol3, mcol4 = st.columns([1,1,1,1])
            mcol1.markdown(f"<div class='neon-card'><h3 style='color:{ACCENT};margin:0'>{total_calls}</h3><div class='small-muted'>Calls Found</div></div>", unsafe_allow_html=True)
            mcol2.markdown(f"<div class='neon-card'><h3 style='color:{ACCENT};margin:0'>{total_rtp_packets}</h3><div class='small-muted'>Total RTP Packets</div></div>", unsafe_allow_html=True)
            mcol3.markdown(f"<div class='neon-card'><h3 style='color:{ACCENT};margin:0'>{avg_duration}</h3><div class='small-muted'>Avg Duration (s)</div></div>", unsafe_allow_html=True)
            mcol4.markdown(f"<div class='neon-card'><h3 style='color:{ACCENT};margin:0'>voip-tracer</h3><div class='small-muted'>Status</div></div>", unsafe_allow_html=True)

            st.markdown("---")

            
            summary_rows = []
            for r in results:
                summary_rows.append({
                    "Call ID": r["call_id"],
                    "From": r["from"],
                    "To": r["to"],
                    "Start": r["start_time"],
                    "End": r["end_time"],
                    "Duration (s)": r["duration_s"],
                    "Total RTP Packets": r["total_rtp_packets"]
                })
            st.subheader("Call Summary")
            st.dataframe(pd.DataFrame(summary_rows))

            # Detailed per-call display with visualizations
            for r in results:
                st.markdown("---")
                st.subheader(f"Call: {r['call_id']}")
                st.write(f"From: {r['from']}  |  To: {r['to']}  |  Duration(s): {r['duration_s']}")
                if r["rtp_flow_summaries"]:
                    # Build flow_df for display (same as original)
                    flow_df_rows = []
                    for f in r["rtp_flow_summaries"]:
                        src, dst, sport, dport = f["flow"]
                        flow_df_rows.append({
                            "src_ip": src,
                            "dst_ip": dst,
                            "src_port": sport,
                            "dst_port": dport,
                            "packets": f["packets"],
                            "packet_loss_pct": f["packet_loss_pct"],
                            "jitter_ms": f["jitter_ms"]
                        })
                    flow_df = pd.DataFrame(flow_df_rows)
                    st.table(flow_df)

                    # For each flow, show visualizations in tabs
                    for f in r["rtp_flow_summaries"]:
                        flow_key = f["flow"]
                        src, dst, sport, dport = flow_key
                        key_label = f"{src}:{sport} → {dst}:{dport}"
                        st.markdown(f"**Flow:** {key_label} — packets: {f['packets']}, loss: {f['packet_loss_pct']}%, jitter: {f['jitter_ms']} ms")

                        alerts = detect_voip_issues(
                                f["jitter_ms"],
                                f["packet_loss_pct"],
                                f["packets"])

                        for level, message in alerts:
                                if level == "CRITICAL":
                                    st.error(message)
                                elif level == "HIGH":
                                    st.error(message)
                                elif level == "MEDIUM":
                                    st.warning(message)
                                else:
                                    st.info(message)
                        # fetch pktlist from rtp_flows_for_vis (built separately)
                        pktlist = rtp_flows_for_vis.get(flow_key, []) or rtp_flows_for_vis.get((dst, src, dport, sport), [])

                        # Create tabs for clean UI
                        tab_wave, tab_seq, tab_jit, tab_mos = st.tabs(["Waveform", "Seq & Gaps", "Jitter", "Quality"])

                        if pktlist:
                            # ensure times are datetime objects (they already are)
                            # Waveform
                            wfig = plot_rtp_waveform(pktlist, title=f"Waveform — {key_label}")
                            with tab_wave:
                                if wfig:
                                    st.plotly_chart(wfig, use_container_width=True,  key=f"waveform_{r['call_id']}_{src}_{dst}_{sport}_{dport}") 
                                    st.caption("Waveform: payload length (bytes) over time. Hover points to see seq/time.")
                                else:
                                    st.info("No RTP payload data for waveform.")

                            # Sequence vs time and gaps
                            sfig = plot_seq_time_and_gaps(pktlist, title=f"Seq vs Time — {key_label}")
                            with tab_seq:
                                if sfig:
                                    st.plotly_chart(sfig, use_container_width=True,  key=f"seq_{r['call_id']}_{src}_{dst}_{sport}_{dport}")
                                    st.caption("Sequence numbers vs time. Red X shows detected sequence gaps (packet loss).")
                                else:
                                    st.info("No sequence data available.")

                            # Jitter
                            jfig = plot_jitter_time(pktlist, window=8, title=f"Jitter (rolling) — {key_label}")
                            with tab_jit:
                                if jfig:
                                    st.plotly_chart(jfig, use_container_width=True, key=f"jitter_{r['call_id']}_{src}_{dst}_{sport}_{dport}")
                                    st.caption("Rolling std of interarrival times (ms) as a jitter proxy.")
                                else:
                                    st.info("Not enough packets to compute jitter.")

                            # MOS estimation and gauge
                            # compute avg jitter from interarrival times
                            times = [p['time'] for p in pktlist if p.get('time') is not None]
                            if len(times) >= 2:
                                iats = np.diff(np.array([t.timestamp() for t in times])) * 1000.0
                                avg_jitter_ms = float(np.std(iats))
                            else:
                                avg_jitter_ms = 0.0
                            seqs = [p['seq'] for p in pktlist if p.get('seq') is not None]
                            loss_pct = 0.0
                            if seqs:
                                expected = max(seqs) - min(seqs) + 1
                                if expected > 0 and len(seqs) < expected:
                                    loss_pct = round((expected - len(seqs)) / expected * 100.0, 2)
                            mos = estimate_mos(avg_jitter_ms, loss_pct)
                            mfig = plot_mos_gauge(mos, title=f"Estimated MOS — {key_label}")
                            with tab_mos:
                                st.plotly_chart(mfig, use_container_width=True,  key=f"mos_{r['call_id']}_{src}_{dst}_{sport}_{dport}")
                                st.caption(f"Avg jitter: {avg_jitter_ms:.2f} ms  •  Estimated packet loss: {loss_pct:.2f}%  •  MOS: {mos}")
                        else:
                            # No pktlist / no RTP flows found for this flow key
                            with tab_wave:
                                st.info("No RTP packets available for this flow (not found in raw PCAP).")
                            with tab_seq:
                                st.info("No sequence data.")
                            with tab_jit:
                                st.info("No jitter data.")
                            with tab_mos:
                                st.info("MOS unavailable (no RTP packets).")

                    # also show a compact interactive bar of packets per flow
                    try:
                        fig_packets = px.bar(flow_df, x=flow_df["src_port"].astype(str) + "→" + flow_df["dst_port"].astype(str),
                                             y="packets", title=f"RTP packets per flow ({r['call_id']})", template="plotly_dark")
                        st.plotly_chart(fig_packets, use_container_width=True, key=f"packets_bar_{r['call_id']}")
                    except Exception:
                        pass

                else:
                    st.info("No RTP flows correlated to this SIP session.")

            # CSV download
            csv_buffer = io.StringIO()
            csv_df.to_csv(csv_buffer, index=False)
            st.download_button("Download call report (.csv)", data=csv_buffer.getvalue(),
                               file_name="voip_call_report.csv", mime="text/csv")

# If not run yet, show small instructions
else:
    st.info("Upload PCAP files or select samples from data/, then click Run Analysis. Use small PCAPs for faster demo.")
