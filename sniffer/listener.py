import socket
import threading
import time
import random
import sys
import struct
from sniffer.parser import parse_ethernet, parse_ipv4, parse_tcp, parse_udp

class PacketListener(threading.Thread):
    def __init__(self, packet_queue, simulate=False):
        super().__init__()
        self.packet_queue = packet_queue
        self.simulate = simulate
        self.running = True
        self.daemon = True
        self.raw_socket = None

    def _push_to_queues(self, packet_info):
        """Pushes parsed packet details to single queue or list of subscriber queues."""
        if isinstance(self.packet_queue, list):
            for q in self.packet_queue:
                q.put(packet_info)
        else:
            self.packet_queue.put(packet_info)

    def get_local_ip(self):
        """Attempts to discover the main local IP address of the system."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't need to be reachable, just triggers interface selection
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def setup_raw_socket(self):
        """Attempts to set up raw socket depending on OS."""
        if self.simulate:
            print("[Listener] Starting in SIMULATION mode.")
            return True

        try:
            if sys.platform.startswith('win'):
                # Windows raw socket setup at IP layer (requires Admin)
                local_ip = self.get_local_ip()
                print(f"[Listener] Windows detected. Attempting raw socket bind to: {local_ip}")
                self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.raw_socket.bind((local_ip, 0))
                # Set socket options to receive all packets (promiscuous mode)
                self.raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                print("[Listener] Promiscuous mode enabled on Windows raw socket.")
            else:
                # Linux/macOS raw socket setup at link layer (requires sudo)
                print("[Listener] Unix-like OS detected. Attempting link-layer raw socket bind (AF_PACKET).")
                self.raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            return True
        except PermissionError:
            print("[Listener] Permission Denied! Raw sockets require Administrator/root privileges.")
            print("[Listener] Falling back to SIMULATION mode.")
            self.simulate = True
            return True
        except Exception as e:
            print(f"[Listener] Failed to initialize raw socket: {e}")
            print("[Listener] Falling back to SIMULATION mode.")
            self.simulate = True
            return True

    def run(self):
        if not self.setup_raw_socket():
            return

        if self.simulate:
            self.run_simulation()
        else:
            self.run_live()

    def run_live(self):
        print("[Listener] Live packet capture started.")
        while self.running:
            try:
                # Receive buffer
                raw_data, addr = self.raw_socket.recvfrom(65535)
                packet_time = time.time()
                
                packet_info = {
                    'time': packet_time,
                    'length': len(raw_data),
                    'protocol': 'OTHER',
                    'src_ip': 'Unknown',
                    'dest_ip': 'Unknown',
                    'src_port': None,
                    'dest_port': None,
                    'info': ''
                }

                if sys.platform.startswith('win'):
                    # Windows raw socket begins directly at IPv4 header (no Ethernet header)
                    ip_data = parse_ipv4(raw_data)
                    if ip_data:
                        packet_info.update({
                            'src_ip': ip_data['src_ip'],
                            'dest_ip': ip_data['dest_ip'],
                        })
                        self._parse_transport(ip_data['proto'], ip_data['payload'], packet_info)
                else:
                    # Linux raw socket begins at Ethernet frame header
                    eth_data = parse_ethernet(raw_data)
                    if eth_data:
                        packet_info['dest_mac'] = eth_data['dest_mac']
                        packet_info['src_mac'] = eth_data['src_mac']
                        # 0x0800 in host byte order is 2048 (IPv4)
                        if eth_data['proto'] == 8:
                            ip_data = parse_ipv4(eth_data['payload'])
                            if ip_data:
                                packet_info.update({
                                    'src_ip': ip_data['src_ip'],
                                    'dest_ip': ip_data['dest_ip'],
                                })
                                self._parse_transport(ip_data['proto'], ip_data['payload'], packet_info)

                self._push_to_queues(packet_info)
            except Exception as e:
                # Avoid crashing on reading bad packets
                if not self.running:
                    break
                continue

    def _parse_transport(self, proto_num, payload, packet_info):
        """Parses TCP/UDP details and updates packet info."""
        if proto_num == 6:  # TCP
            packet_info['protocol'] = 'TCP'
            tcp_data = parse_tcp(payload)
            if tcp_data:
                packet_info.update({
                    'src_port': tcp_data['src_port'],
                    'dest_port': tcp_data['dest_port'],
                })
                # Create flag info summary
                active_flags = [k.upper() for k, v in tcp_data['flags'].items() if v]
                packet_info['info'] = f"Flags: {','.join(active_flags)} | Seq: {tcp_data['seq']}"
        elif proto_num == 17:  # UDP
            packet_info['protocol'] = 'UDP'
            udp_data = parse_udp(payload)
            if udp_data:
                packet_info.update({
                    'src_port': udp_data['src_port'],
                    'dest_port': udp_data['dest_port'],
                    'info': f"Len: {udp_data['size']}"
                })
        else:
            packet_info['protocol'] = f'IP-Proto {proto_num}'

    def run_simulation(self):
        """Simulates network traffic by constructing and parsing mock packet bytes."""
        print("[Listener] Packet generator simulation loop started.")
        
        # Simulated devices
        ips = [
            '192.168.1.5',   # User PC
            '192.168.1.10',  # Web Server
            '192.168.1.1',   # Router
            '8.8.8.8',       # Google DNS
            '104.244.42.1',  # External Web IP
            '192.168.1.102'  # Mock printer/IoT
        ]
        
        macs = [
            struct.pack('! 6B', 0x00, 0x0c, 0x29, 0x3e, 0x4f, 0x01),
            struct.pack('! 6B', 0x00, 0x0c, 0x29, 0x3e, 0x4f, 0x02),
            struct.pack('! 6B', 0x00, 0x0c, 0x29, 0x3e, 0x4f, 0x03),
            struct.pack('! 6B', 0x00, 0x0c, 0x29, 0x3e, 0x4f, 0x04)
        ]

        # Port scanner simulation variables
        scan_state = {
            'is_scanning': False,
            'attacker_ip': '10.0.0.99',
            'current_port': 1,
            'scan_target_ip': '192.168.1.10',
            'packets_sent': 0
        }

        while self.running:
            # Control simulation speed
            time.sleep(random.uniform(0.02, 0.15))
            
            # Periodically start/stop a port scan attack simulation
            if not scan_state['is_scanning'] and random.random() < 0.02:
                scan_state['is_scanning'] = True
                scan_state['attacker_ip'] = f"198.51.100.{random.randint(2, 254)}"
                scan_state['scan_target_ip'] = random.choice(['192.168.1.5', '192.168.1.10'])
                scan_state['current_port'] = random.randint(10, 100)
                scan_state['packets_sent'] = 0
                print(f"[Simulator] Triggering port scan simulation from {scan_state['attacker_ip']}")

            # Generate packet details
            is_scan_packet = False
            if scan_state['is_scanning']:
                # Generate a scan packet: TCP SYN to sequential ports
                src_ip = scan_state['attacker_ip']
                dest_ip = scan_state['scan_target_ip']
                proto = 6  # TCP
                src_port = random.randint(49152, 65535)
                dest_port = scan_state['current_port']
                tcp_flags = 2  # SYN flag
                
                # Advance port scanning state
                scan_state['current_port'] += random.randint(1, 5)
                scan_state['packets_sent'] += 1
                is_scan_packet = True
                
                if scan_state['packets_sent'] > 40 or scan_state['current_port'] > 1024:
                    scan_state['is_scanning'] = False
            else:
                # Regular random traffic
                src_ip = random.choice(ips)
                dest_ip = random.choice(ips)
                while dest_ip == src_ip:
                    dest_ip = random.choice(ips)
                
                proto = random.choice([6, 6, 6, 17, 17, 99])  # Bias toward TCP/UDP
                src_port = random.randint(1024, 65535)
                dest_port = random.choice([80, 443, 53, 22, 3389, random.randint(1024, 65535)])
                tcp_flags = random.choice([2, 16, 18, 24])  # SYN, ACK, SYN-ACK, PSH-ACK

            # Build binary representations of packet to execute the actual parser
            try:
                # Pack transport
                if proto == 6:  # TCP
                    # offset & flags: offset of 5 words (20 bytes) = 0x5000. Combine with flags.
                    offset_flags = 0x5000 | tcp_flags
                    transport_bytes = struct.pack('! H H I I H H H H', src_port, dest_port, 1000, 2000, offset_flags, 1024, 0, 0)
                elif proto == 17:  # UDP
                    transport_bytes = struct.pack('! H H H H', src_port, dest_port, 15, 0)
                else:  # Other
                    transport_bytes = b'RAW DATA PAYLOAD'

                # Pack IPv4 (20 bytes)
                src_ip_bytes = socket.inet_aton(src_ip)
                dest_ip_bytes = socket.inet_aton(dest_ip)
                # TTL = 64, Protocol = proto
                ip_header = struct.pack('! B B H H H B B H 4s 4s', 0x45, 0, 20 + len(transport_bytes), 54321, 0, 64, proto, 0, src_ip_bytes, dest_ip_bytes)
                
                # Pack Ethernet (14 bytes)
                eth_header = struct.pack('! 6s 6s H', random.choice(macs), random.choice(macs), 0x0800)
                
                # Full packet
                raw_data = eth_header + ip_header + transport_bytes
                packet_time = time.time()
                
                # Run the actual parser on the generated bytes
                packet_info = {
                    'time': packet_time,
                    'length': len(raw_data),
                    'protocol': 'OTHER',
                    'src_ip': 'Unknown',
                    'dest_ip': 'Unknown',
                    'src_port': None,
                    'dest_port': None,
                    'info': ''
                }
                
                eth_data = parse_ethernet(raw_data)
                if eth_data:
                    packet_info['dest_mac'] = eth_data['dest_mac']
                    packet_info['src_mac'] = eth_data['src_mac']
                    if eth_data['proto'] == 8: # 0x0800 -> 8 in h-tons or htons conversion
                        ip_data = parse_ipv4(eth_data['payload'])
                        if ip_data:
                            packet_info.update({
                                'src_ip': ip_data['src_ip'],
                                'dest_ip': ip_data['dest_ip'],
                            })
                            self._parse_transport(ip_data['proto'], ip_data['payload'], packet_info)
                            
                self._push_to_queues(packet_info)
            except Exception as e:
                # Silence generator packet pack/unpack safety
                continue

    def stop(self):
        self.running = False
        if self.raw_socket:
            try:
                if sys.platform.startswith('win'):
                    self.raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            self.raw_socket.close()
