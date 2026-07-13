import threading
import time
from collections import defaultdict

class AnomalyDetector(threading.Thread):
    def __init__(self, packet_queue, alerts_queue, window_seconds=10, port_scan_threshold=15, pps_threshold=80):
        super().__init__()
        self.packet_queue = packet_queue
        self.alerts_queue = alerts_queue
        self.window_seconds = window_seconds
        
        # Thresholds
        self.port_scan_threshold = port_scan_threshold
        self.pps_threshold = pps_threshold  # Packets per second from single IP
        
        self.running = True
        self.daemon = True
        
        # State tracking: IP -> list of (timestamp, port)
        self.ip_port_history = defaultdict(list)
        # State tracking: IP -> list of timestamps
        self.ip_packet_history = defaultdict(list)
        
        # Cooldown to avoid spamming the same alert repeatedly: (IP, AlertType) -> last_alert_time
        self.alert_cooldown = {}
        self.cooldown_period = 8.0  # seconds

    def run(self):
        print("[Detector] Anomaly detection thread started.")
        last_cleanup = time.time()
        
        while self.running:
            try:
                # Read packet from queue with a timeout to allow checking self.running and cleaning up
                packet = self.packet_queue.get(timeout=1.0)
                
                # Process the packet
                self.process_packet(packet)
                
                # Signal task completion
                self.packet_queue.task_done()
                
            except Exception:  # Timeout or empty queue
                pass
            
            # Periodically clean up old tracking records to prevent memory leak
            now = time.time()
            if now - last_cleanup > 5.0:
                self.cleanup_history(now)
                last_cleanup = now

    def process_packet(self, packet):
        src_ip = packet.get('src_ip')
        dest_ip = packet.get('dest_ip')
        dest_port = packet.get('dest_port')
        now = packet.get('time', time.time())
        
        # Skip parsing if IP details are unknown/localhost multicast
        if src_ip == 'Unknown' or not src_ip:
            return
            
        # 1. Track packet volume for rate limit / DDoS anomaly
        self.ip_packet_history[src_ip].append(now)
        self.check_traffic_volume(src_ip, now)
        
        # 2. Track port scan anomaly (if TCP/UDP packet with a port)
        if dest_port is not None:
            self.ip_port_history[src_ip].append((now, dest_port))
            self.check_port_scanning(src_ip, dest_ip, now)

    def check_traffic_volume(self, src_ip, now):
        # Filter packet history for this IP in the sliding window
        window_start = now - self.window_seconds
        self.ip_packet_history[src_ip] = [t for t in self.ip_packet_history[src_ip] if t >= window_start]
        
        packets_count = len(self.ip_packet_history[src_ip])
        pps = packets_count / self.window_seconds  # packets per second average in window
        
        if pps > self.pps_threshold:
            self.trigger_alert(
                alert_type="TRAFFIC_VOLUME",
                src_ip=src_ip,
                dest_ip="Multiple/Broadcast",
                details=f"High packet rate: {pps:.1f} packets/s (Threshold: {self.pps_threshold} pps)",
                severity="HIGH",
                now=now
            )

    def check_port_scanning(self, src_ip, dest_ip, now):
        # Filter port history for this IP in the sliding window
        window_start = now - self.window_seconds
        self.ip_port_history[src_ip] = [(t, p) for (t, p) in self.ip_port_history[src_ip] if t >= window_start]
        
        # Get unique ports scanned in this window
        unique_ports = {port for (t, port) in self.ip_port_history[src_ip]}
        unique_port_count = len(unique_ports)
        
        if unique_port_count > self.port_scan_threshold:
            self.trigger_alert(
                alert_type="PORT_SCAN",
                src_ip=src_ip,
                dest_ip=dest_ip,
                details=f"Scanned {unique_port_count} unique ports in {self.window_seconds}s (Threshold: {self.port_scan_threshold} ports)",
                severity="HIGH",
                now=now
            )

    def trigger_alert(self, alert_type, src_ip, dest_ip, details, severity, now):
        cooldown_key = (src_ip, alert_type)
        last_alert = self.alert_cooldown.get(cooldown_key, 0)
        
        # Check cooldown to prevent flooding the dashboard with identical alerts
        if now - last_alert > self.cooldown_period:
            self.alert_cooldown[cooldown_key] = now
            
            alert = {
                'time': now,
                'type': alert_type,
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'details': details,
                'severity': severity
            }
            
            print(f"[Detector] [ALERT - {severity}] {alert_type} from {src_ip} -> {details}")
            self.alerts_queue.put(alert)

    def cleanup_history(self, now):
        """Cleans up expired data from tracking histories."""
        window_start = now - self.window_seconds
        
        # Clean port scanning history
        expired_ips = []
        for ip, history in self.ip_port_history.items():
            self.ip_port_history[ip] = [(t, p) for (t, p) in history if t >= window_start]
            if not self.ip_port_history[ip]:
                expired_ips.append(ip)
        for ip in expired_ips:
            del self.ip_port_history[ip]
            
        # Clean packet frequency history
        expired_ips = []
        for ip, history in self.ip_packet_history.items():
            self.ip_packet_history[ip] = [t for t in history if t >= window_start]
            if not self.ip_packet_history[ip]:
                expired_ips.append(ip)
        for ip in expired_ips:
            del self.ip_packet_history[ip]

        # Clean cooldown history
        expired_cooldowns = [k for k, t in self.alert_cooldown.items() if now - t > 60]
        for k in expired_cooldowns:
            del self.alert_cooldown[k]

    def stop(self):
        self.running = False
