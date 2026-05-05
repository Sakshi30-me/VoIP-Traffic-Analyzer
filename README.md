# 📞 VoIP Traffic Analyzer (PCAP-Based)

A Python-based network analysis tool designed to **analyze VoIP traffic from PCAP files**, detect RTP streams, and evaluate **call quality metrics such as jitter, packet loss, and MOS**.

Built with a **SOC (Security Operations Center) perspective**, this project goes beyond visualization by identifying **potential anomalies and VoIP-related issues**.

---

## 🚀 Key Features

* 📂 Upload and analyze `.pcap` / `.pcapng` files
* 📡 Automatic detection of **SIP sessions & RTP streams**
* 📊 Real-time visualization using **Plotly + Streamlit**
* 📉 Metrics:

  * Jitter (ms)
  * Packet Loss (%)
  * RTP Packet Count
  * Call Duration
* 📈 MOS (Mean Opinion Score) estimation
* 🚨 **SOC Detection Layer**

  * High jitter detection
  * Packet loss alerts
  * Potential VoIP DoS indicators
* 📥 Export analysis report as CSV

---

## 🧠 Why This Project?

In real-world SOC environments, analysts don’t just inspect packets — they:

* Detect anomalies
* Identify degraded service conditions
* Correlate network behavior with potential threats

This tool simulates that workflow by converting **network-level data into actionable insights**.

---

## 🛠️ Tech Stack

* **Python**
* **Streamlit** (UI)
* **Scapy** (Packet parsing)
* **Pandas / NumPy** (Data processing)
* **Plotly** (Visualization)

---

## ⚙️ How It Works

1. Upload PCAP file(s)
2. Tool extracts:

   * SIP signaling data
   * RTP packet streams
3. Calculates:

   * Packet sequence gaps → Packet Loss
   * Interarrival delay → Jitter
4. Generates:

   * Graphs (Waveform, Jitter, Sequence)
   * MOS Score
5. Applies:

   * SOC Detection Rules for anomaly identification

---

## 📊 Sample Output

* RTP Flow Analysis Table
* Jitter Graph
* Packet Loss Detection (Sequence Gaps)
* MOS Quality Gauge
* CSV Report Export

---

## 📁 Project Structure

```
voip-tracker/
│
├── voip.py                # Main Streamlit application
├── data/                  # Sample PCAP files (optional)
├── outputs/               # Generated CSV reports
├── requirements.txt       # Dependencies
└── README.md
```

---

## ▶️ Running the Project

```bash
pip install -r requirements.txt
streamlit run voip.py
```

---

## 📌 SOC Use Case

This project can be mapped to:

* Network Traffic Analysis (NTA)
* VoIP Monitoring
* Incident Investigation (packet-level)
* Detection of:

  * Network congestion
  * Packet drops
  * Potential DoS behavior in VoIP systems

---

## ⚠️ Note

* This project is for **educational and analytical purposes**
* Do not upload sensitive or real organizational traffic without authorization

---

## 👩‍💻 Author

**Sakshi Maurya**
Cybersecurity Analyst | SOC Operations | Threat Detection | Digital Forensics

🔗 LinkedIn: https://www.linkedin.com/in/sakshi-maurya-824931302/
🔗 GitHub: https://github.com/Sakshi30-me

---

## ⭐ Future Improvements

* Attack classification (DoS vs congestion)
* Live packet capture support
* SIEM integration (Splunk / ELK)
* Alert timeline visualization

---
