import json
import time
import queue
import threading
from collections import deque, Counter
from flask import Flask, render_template, Response

# Global statistics and active SSE clients list
stats = {
    'total_packets': 0,
    'total_bytes': 0,
    'protocols': Counter(),
    'ports': Counter(),
    'recent_packets': deque(maxlen=30)
}

alerts_log = deque(maxlen=20)
stats_lock = threading.Lock()

# List of client queues for SSE broadcasting
sse_clients = []
clients_lock = threading.Lock()

# Bandwidth and PPS tracking
traffic_history = deque(maxlen=60) # Store last 60 seconds of pps
current_sec_packets = 0
current_sec_bytes = 0
sec_tracker_time = time.time()
pps_lock = threading.Lock()

def stats_worker(packet_queue, alerts_queue):
    """Background worker that updates statistics and broadcasts events to all SSE clients."""
    global current_sec_packets, current_sec_bytes, sec_tracker_time
    
    # Thread to handle alerts queue specifically so they are broadcast instantly
    def alerts_handler():
        while True:
            try:
                alert = alerts_queue.get()
                with stats_lock:
                    alerts_log.appendleft(alert)
                
                # Broadcast alert immediately to all active SSE clients
                message = {
                    'event_type': 'alert',
                    'data': alert
                }
                broadcast_sse_message(message)
                alerts_queue.task_done()
            except Exception as e:
                print(f"[StatsWorker] Alert handler error: {e}")
                time.sleep(1)

    t_alerts = threading.Thread(target=alerts_handler, daemon=True)
    t_alerts.start()

    # Main stats loop (reads packets)
    last_broadcast_time = time.time()
    
    while True:
        try:
            # Fetch packet with timeout to allow periodic broadcasts even if network is idle
            packet = packet_queue.get(timeout=0.1)
            
            # Update stats
            with stats_lock:
                stats['total_packets'] += 1
                stats['total_bytes'] += packet['length']
                stats['protocols'][packet['protocol']] += 1
                if packet['dest_port'] is not None:
                    stats['ports'][packet['dest_port']] += 1
                stats['recent_packets'].appendleft(packet)

            # Update real-time PPS and Bandwidth
            with pps_lock:
                current_sec_packets += 1
                current_sec_bytes += packet['length']

            packet_queue.task_done()
        except queue.Empty:
            pass
        except Exception as e:
            print(f"[StatsWorker] Packet processor error: {e}")
            
        # Update PPS history and broadcast statistics once every 500ms
        now = time.time()
        
        # Every 1.0 second, slide the PPS window
        global sec_tracker_time
        if now - sec_tracker_time >= 1.0:
            with pps_lock:
                pps = current_sec_packets
                kbps = (current_sec_bytes * 8) / 1024.0 # kilobits per second
                traffic_history.append({
                    'time': time.strftime('%H:%M:%S', time.localtime(now)),
                    'pps': pps,
                    'kbps': round(kbps, 2)
                })
                current_sec_packets = 0
                current_sec_bytes = 0
                sec_tracker_time = now
                
        # Every 500ms, broadcast stats to frontend
        if now - last_broadcast_time >= 0.5:
            last_broadcast_time = now
            
            # Get latest snapshot under lock
            with stats_lock:
                # Top 10 destination ports
                top_ports = stats['ports'].most_common(10)
                
                # Convert protocol counter to normal dict
                protocols_dict = dict(stats['protocols'])
                
                # Fetch recent packets list
                recent_list = list(stats['recent_packets'])
                
                # Get current alerts list
                current_alerts = list(alerts_log)
                
            # Get latest traffic history snapshot
            with pps_lock:
                traffic_list = list(traffic_history)
                latest_pps = traffic_list[-1]['pps'] if traffic_list else 0
                latest_kbps = traffic_list[-1]['kbps'] if traffic_list else 0.0

            stats_payload = {
                'total_packets': stats['total_packets'],
                'total_bytes': stats['total_bytes'],
                'protocols': protocols_dict,
                'top_ports': top_ports,
                'recent_packets': recent_list,
                'traffic_history': traffic_list,
                'current_pps': latest_pps,
                'current_kbps': latest_kbps,
                'alerts_count': len(current_alerts)
            }
            
            broadcast_sse_message({
                'event_type': 'stats',
                'data': stats_payload
            })

def broadcast_sse_message(message):
    """Sends JSON message to all registered client queues."""
    formatted_msg = f"event: {message['event_type']}\ndata: {json.dumps(message['data'])}\n\n"
    
    with clients_lock:
        closed_clients = []
        for client_q in sse_clients:
            try:
                client_q.put_nowait(formatted_msg)
            except queue.Full:
                # Client queue is full, indicating client might have disconnected
                closed_clients.append(client_q)
        
        # Cleanup closed clients
        for client_q in closed_clients:
            if client_q in sse_clients:
                sse_clients.remove(client_q)

def create_app(packet_queue, alerts_queue):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'sniffer_secret_key'

    # Start the statistics worker thread
    t = threading.Thread(target=stats_worker, args=(packet_queue, alerts_queue), daemon=True)
    t.start()

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/stream')
    def stream():
        """SSE endpoint returning a generator yielding real-time packet stats and alerts."""
        client_q = queue.Queue(maxsize=100)
        
        with clients_lock:
            sse_clients.append(client_q)
            
        print(f"[Web] New SSE client connection established. Active clients: {len(sse_clients)}")

        def event_generator():
            try:
                # Send initial system configuration
                yield f"event: system\ndata: {json.dumps({'status': 'connected'})}\n\n"
                
                while True:
                    # Get message from private queue and send to client
                    msg = client_q.get()
                    yield msg
            except GeneratorExit:
                # Triggered when client closes the SSE tab
                pass
            finally:
                with clients_lock:
                    if client_q in sse_clients:
                        sse_clients.remove(client_q)
                print(f"[Web] SSE client disconnected. Active clients: {len(sse_clients)}")

        return Response(event_generator(), mimetype='text/event-stream')

    return app
