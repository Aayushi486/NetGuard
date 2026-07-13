# AETHER: Code & Logic Guide

This quick guide explains how the code is structured, the underlying mechanisms, and the key code snippets.

---

## 1. How Sockets & Decoders Work (`sniffer/`)

The sniffer intercepts raw internet traffic. This traffic arrives as binary strings. We parse the protocol headers using Python's `struct` library.

### Unpacking Binary Headers (`sniffer/parser.py`)
Each layer (Ethernet, IP, TCP, UDP) has a strictly defined header size and structure.
For example, the first 20 bytes of an IPv4 packet look like this:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Source IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination IP Address                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

In `sniffer/parser.py`, we unpack this block using a format string `! 8x B B 2x 4s 4s`:
- `!`: Network byte order (big-endian).
- `8x`: Skip the first 8 bytes (Version, IHL, TOS, Length, ID, Flags).
- `B`: Unpack 1 byte (TTL).
- `B`: Unpack 1 byte (Protocol: e.g., `6` for TCP, `17` for UDP).
- `2x`: Skip 2 bytes (Header Checksum).
- `4s`: Unpack a 4-byte string (Source IP bytes).
- `4s`: Unpack a 4-byte string (Destination IP bytes).

```python
# Unpacking IPv4 details
ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
src_ip = socket.inet_ntoa(src)  # Converts 4 bytes (e.g. \xc0\xa8\x01\x05) to "192.168.1.5"
```

---

## 2. Threat Detection Logic (`detector/`)

The anomaly detector checks incoming packets for suspicious patterns inside a sliding time window (10 seconds).

### Sliding-Window Port Scan Detection (`detector/anomaly_detector.py`)
When a packet is received, we store its timestamp and target port:
```python
# Record the port targeted by this IP address
self.ip_port_history[src_ip].append((now, dest_port))
```

We then prune any entries older than our 10-second window, and calculate the count of *unique* ports:
```python
# 1. Filter out records older than 10 seconds
window_start = now - 10
self.ip_port_history[src_ip] = [(t, p) for (t, p) in self.ip_port_history[src_ip] if t >= window_start]

# 2. Extract unique ports targeted in the active window
unique_ports = {port for (t, port) in self.ip_port_history[src_ip]}

# 3. Check if count exceeds limit (threshold)
if len(unique_ports) > self.port_scan_threshold:
    self.trigger_alert("PORT_SCAN", src_ip, dest_ip, ...)
```

---

## 3. Streaming Data to Browser (`web/`)

Web applications usually require the browser to ask for data (request/response). To stream stats in real-time, AETHER uses **Server-Sent Events (SSE)**.

### Streaming with SSE (`web/app.py`)
Flask serves a continuous text stream using Python generators. The browser keeps the HTTP connection open:
```python
@app.route('/stream')
def stream():
    def event_generator():
        while True:
            # Wait for the next statistic/alert message from queue
            msg = client_q.get()
            # Yield in standard SSE format (event: name \n data: payload \n\n)
            yield msg
            
    return Response(event_generator(), mimetype='text/event-stream')
```

In the browser (`web/static/js/dashboard.js`), we open this stream using the native `EventSource` interface:
```javascript
const eventSource = new EventSource('/stream');

// Automatically triggers when a new stat packet is pushed by Flask
eventSource.addEventListener('stats', (e) => {
    const stats = JSON.parse(e.data);
    updateDashboardCharts(stats);  // Redraws Line, Doughnut, and Bar charts
});
```
