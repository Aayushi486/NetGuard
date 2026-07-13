import struct
import socket

def get_mac_addr(bytes_addr):
    """Convert bytes representation of MAC address to readable string (e.g. AA:BB:CC:DD:EE:FF)."""
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

def get_ip_addr(bytes_addr):
    """Convert 4-byte IP address to string representation (e.g. 192.168.1.1)."""
    return socket.inet_ntoa(bytes_addr)

def parse_ethernet(data):
    """
    Parse Ethernet frame header.
    Ethernet Header:
    Destination MAC (6s), Source MAC (6s), EtherType (H) -> Total 14 bytes
    """
    if len(data) < 14:
        return None
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return {
        'dest_mac': get_mac_addr(dest_mac),
        'src_mac': get_mac_addr(src_mac),
        'proto': socket.htons(eth_proto),
        'payload': data[14:]
    }

def parse_ipv4(data):
    """
    Parse IPv4 header.
    IPv4 Header:
    Version & IHL (B), TOS (B), Total Length (H), Identification (H), Flags & Fragment (H),
    TTL (B), Protocol (B), Header Checksum (H), Source IP (4s), Destination IP (4s) -> Total 20 bytes
    """
    if len(data) < 20:
        return None
    
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    
    if len(data) < header_len:
        return None
        
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return {
        'version': version,
        'header_len': header_len,
        'ttl': ttl,
        'proto': proto,  # 6 = TCP, 17 = UDP
        'src_ip': get_ip_addr(src),
        'dest_ip': get_ip_addr(target),
        'payload': data[header_len:]
    }

def parse_tcp(data):
    """
    Parse TCP header.
    TCP Header:
    Source Port (H), Destination Port (H), Seq Num (I), Ack Num (I),
    Offset & Flags (H), Window (H), Checksum (H), Urgent Pointer (H) -> Total 20 bytes
    """
    if len(data) < 20:
        return None
        
    src_port, dest_port, seq, ack, offset_flags = struct.unpack('! H H I I H', data[:14])
    
    # Offset is the upper 4 bits of offset_flags, representing length in 32-bit words
    offset = (offset_flags >> 12) * 4
    
    if len(data) < offset:
        return None
        
    # Extract TCP Flags
    flags = {
        'fin': offset_flags & 1,
        'syn': (offset_flags & 2) >> 1,
        'rst': (offset_flags & 4) >> 2,
        'psh': (offset_flags & 8) >> 3,
        'ack': (offset_flags & 16) >> 4,
        'urg': (offset_flags & 32) >> 5,
        'ece': (offset_flags & 64) >> 6,
        'cwr': (offset_flags & 128) >> 7
    }
    
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'seq': seq,
        'ack': ack,
        'flags': flags,
        'payload': data[offset:]
    }

def parse_udp(data):
    """
    Parse UDP header.
    UDP Header:
    Source Port (H), Destination Port (H), Length (H), Checksum (H) -> Total 8 bytes
    """
    if len(data) < 8:
        return None
        
    src_port, dest_port, size = struct.unpack('! H H H 2x', data[:8])
    return {
        'src_port': src_port,
        'dest_port': dest_port,
        'size': size,
        'payload': data[8:]
    }
