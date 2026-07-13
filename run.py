import argparse
import sys
import time
import queue
from sniffer.listener import PacketListener
from detector.anomaly_detector import AnomalyDetector
from web.app import create_app

def parse_arguments():
    parser = argparse.ArgumentParser(description="AETHER: Real-Time Network Packet Sniffer & Anomaly Detection System")
    parser.add_argument(
        '--simulate',
        action='store_true',
        help="Force Packet Listener to run in simulation mode (no root/admin rights required)"
    )
    parser.add_argument(
        '--host',
        type=str,
        default='127.0.0.1',
        help="IP address to run the Flask dashboard (default: 127.0.0.1)"
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help="Port number to run the Flask dashboard (default: 5000)"
    )
    parser.add_argument(
        '--scan-threshold',
        type=int,
        default=15,
        help="Number of unique ports targeted within 10s to trigger Port Scan Alert (default: 15)"
    )
    parser.add_argument(
        '--pps-threshold',
        type=int,
        default=80,
        help="Average packets per second from a single IP to trigger Volume Anomaly Alert (default: 80)"
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    print("=" * 65)
    print("      AETHER: REAL-TIME NETWORK SNIFFER & ANOMALY DETECTOR")
    print("=" * 65)

    # Initialize thread-safe queues
    detector_packet_queue = queue.Queue()
    web_packet_queue = queue.Queue()
    alerts_queue = queue.Queue()

    # Broadcaster list of queues for listener
    listener_queues = [detector_packet_queue, web_packet_queue]

    # Initialize background threads
    print("[System] Initializing background threads...")
    
    # Packet Listener
    listener = PacketListener(
        packet_queue=listener_queues, 
        simulate=args.simulate
    )
    
    # Anomaly Detector
    detector = AnomalyDetector(
        packet_queue=detector_packet_queue,
        alerts_queue=alerts_queue,
        window_seconds=10,
        port_scan_threshold=args.scan_threshold,
        pps_threshold=args.pps_threshold
    )

    # Start threads
    detector.start()
    listener.start()

    # Flask app initialization
    # We pass the web packet queue and the alerts queue to the web interface
    app = create_app(web_packet_queue, alerts_queue)

    print("[System] Background threads successfully initialized.")
    print(f"[System] Starting dashboard on http://{args.host}:{args.port}")
    print("Press Ctrl+C to terminate.")
    print("-" * 65)

    try:
        # Run Flask server (disable debug reloader to prevent duplicate subprocesses)
        app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[System] Keyboard interrupt detected. Terminating...")
    except Exception as e:
        print(f"\n[System] Server error encountered: {e}")
    finally:
        # Graceful shutdown of background workers
        print("[System] Shutting down background threads...")
        listener.stop()
        detector.stop()
        
        # Give threads a moment to finish up
        listener.join(timeout=1.0)
        detector.join(timeout=1.0)
        
        print("[System] Clean exit completed.")
        sys.exit(0)

if __name__ == "__main__":
    main()
