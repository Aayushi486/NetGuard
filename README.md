# AETHER: Real-Time Network Packet Sniffer & Multithreaded Anomaly Detector

AETHER is a high-performance, real-time packet sniffer and Intrusion Detection System (IDS) dashboard built in Python. Using raw sockets, AETHER captures, parses, and logs network packets (Ethernet, IPv4, TCP, and UDP). The application employs optimized multithreading to perform real-time security anomaly analysis (such as detecting port scanning and packet flood DOS attacks), and streams metrics dynamically to a premium, glassmorphism-themed Flask web dashboard backed by Chart.js.

---

## Key Features

1. **Raw Sockets Packet Capture**: Binds directly to network interfaces to read raw bytes.
2. **Multi-Layer Protocol Parser**: Manually unpacks binary structures for:
   - **Link Layer**: Ethernet Frame headers (MAC addresses, ethertype)
   - **Network Layer**: IPv4 headers (version, IHL, TTL, Protocol, Source/Destination IPs)
   - **Transport Layer**: TCP (ports, sequence numbers, flags: SYN, ACK, FIN, RST, etc.) and UDP (ports, payload length)
3. **Multithreaded IDS Anomaly Detector**:
   - **Port Scan Detection**: Detects scanning activities by tracking unique destination ports targeted by an IP in a sliding time window.
   - **DoS / Traffic Rate Monitoring**: Flags sudden packet frequency floods exceeding safe limits.
   - Optimized memory management through automatic sliding window history pruning.
4. **Interactive Glassmorphism Dashboard**:
   - Live network throughput tracking (Line Chart).
   - Real-time protocol breakdown (Doughnut Chart).
   - Active Target ports visualization (Horizontal Bar Chart).
   - Event-driven notifications for security threats using Server-Sent Events (SSE).
   - Full packet inspector listing chronological packet captures.
5. **Simulation Mode**: A safe, sandbox mode generating mock network packets and simulating port scan attacks. This allows testing all parts of the dashboard and IDS analysis without needing administrative/root privileges or a busy live interface.

---

## Directory Structure

The project code is organized into decoupled, clean packages:

```
network_sniffer_dashboard/
├── sniffer/
│   ├── __init__.py
│   ├── parser.py          # Header parsing logic (Ethernet, IPv4, TCP, UDP)
│   └── listener.py        # Raw socket listener thread (Windows, Linux, Simulator)
├── detector/
│   ├── __init__.py
│   └── anomaly_detector.py# Threaded sliding-window IDS anomaly detector
├── web/
│   ├── __init__.py
│   ├── app.py             # Flask Web Server & SSE Streaming Endpoints
│   ├── templates/
│   │   └── index.html     # Dashboard layout
│   └── static/
│       ├── css/
│       │   └── style.css  # CSS styling (animations, scrollbars, glowing alarms)
│       └── js/
│           └── dashboard.js # Chart.js visualization & SSE EventSource listener
├── requirements.txt       # Python Dependencies
├── README.md              # Instructions and architecture documentation
└── run.py                 # Application launcher and thread orchestrator
```

---

## Installation & Setup

### 1. Clone & Setup Directory
Copy all files to your target workspace. Or copy the files to your active environment.

### 2. Install Dependencies
Install the required packages using pip:
```bash
pip install -r requirements.txt
```

### 3. Privilege Requirements for Live Capturing
* **Windows**: Run your terminal (Command Prompt/PowerShell) as **Administrator**. The sniffer will bind to your local IP and use promiscuous mode (`SIO_RCVALL`) to capture incoming traffic.
* **Linux**: Run the script with `sudo` privileges:
  ```bash
  sudo python run.py
  ```
  Linux live capture opens an `AF_PACKET` socket which includes raw Ethernet headers.
* **No Privileges / Dev Testing**: Simply run the application in **Simulation Mode** (see below). No admin rights are needed.

---

## Running the Application

### A. Run in Simulation Mode (Recommended for Demos)
To immediately start the system with realistic simulated traffic and periodic port scanning alerts:
```bash
python run.py --simulate
```

### B. Run in Live Sniffing Mode (Requires Admin/Sudo)
To capture real packets passing through your network card:
```bash
# Windows (Run console as Admin) / Linux (using sudo)
python run.py
```

### Command Line Flags
You can customize thresholds and bind details when launching:
```bash
python run.py --host 0.0.0.0 --port 8080 --scan-threshold 10 --pps-threshold 100
```
- `--simulate`: Force simulation traffic.
- `--host`: Flask server IP (default: `127.0.0.1`).
- `--port`: Flask server port (default: `5000`).
- `--scan-threshold`: Number of unique destination ports hit within 10s from a single IP to trigger a Port Scan alert (default: `15`).
- `--pps-threshold`: Packet rate limit from a single IP before flagging a traffic volume alert (default: `80` pps).

---

## How it Works

### 1. Multi-Queue Decoupled Threads
AETHER employs three separate threads to divide labor, ensuring network capturing is not bottlenecked by web server rendering or detection analysis:
1. **Listener Thread**: Binds to the raw socket, reads binary packets, runs the parser, and puts parsed dictionary results into dual queues (`detector_packet_queue` and `web_packet_queue`).
2. **Detector Thread**: Pulls packets from `detector_packet_queue` and updates localized IP traffic sliding histories to check for threat indicators. Pushes alerts to `alerts_queue`.
3. **Flask App & Stats Worker Thread**: Reads from `web_packet_queue` and `alerts_queue` to keep global metrics up-to-date and broadcasts Server-Sent Events (SSE) to connected web browsers.

### 2. Anomaly Detection Logic
* **Port Scanning**: For every packet, the destination port is registered under its Source IP inside a list: `ip_port_history[src_ip].append((timestamp, dest_port))`. On every packet arrival, historical entries older than 10 seconds are pruned. If the number of *unique* ports in the list exceeds the threshold, an alert is pushed.
* **Traffic Volume**: The total packet timestamps for an IP are recorded: `ip_packet_history[src_ip].append(timestamp)`. Older records are pruned. If the average packets-per-second (PPS) exceeds the threshold, a traffic volume alert is raised.
* **Alert Cooldowns**: Once an IP triggers an alert, it enters an 8-second cooldown for that specific threat type to avoid flooding the user dashboard.

---

## Security Disclaimer

This utility is developed solely for network debugging, system administration, and educational research purposes. Sniffing packets on networks where you do not have explicit authorization is illegal. The developers assume no liability for misuse of this tool.
