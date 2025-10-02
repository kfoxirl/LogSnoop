#!/usr/bin/env python3
"""
Generate a sample SKY binary log file for testing.
"""

import struct
import socket
import time
from datetime import datetime


def ip_to_int(ip_str):
    """Convert IP address string to integer."""
    return struct.unpack('>I', socket.inet_aton(ip_str))[0]


def create_sample_sky_log(filename):
    """Create a sample SKY binary log file."""
    
    with open(filename, 'wb') as f:
        # Write header
        
        # Magic bytes
        f.write(b'\x91SKY\r\n\x1a\n')
        
        # Version (1 byte)
        f.write(struct.pack('B', 1))
        
        # Creation timestamp (4 bytes, big-endian)
        creation_time = int(time.time())
        f.write(struct.pack('>I', creation_time))
        
        # Hostname
        hostname = "logsnoop-test"
        hostname_bytes = hostname.encode('utf-8')
        f.write(struct.pack('>I', len(hostname_bytes)))  # Hostname length
        f.write(hostname_bytes)  # Hostname
        
        # Flag (Base64 encoded)
        import base64
        original_flag = "SKY-PARS-7325"  # This will be Base64 encoded
        flag = base64.b64encode(original_flag.encode('utf-8')).decode('ascii')  # U0tZLVBBUlMtNzMyNQ==
        flag_bytes = flag.encode('utf-8')
        f.write(struct.pack('>I', len(flag_bytes)))  # Flag length  
        f.write(flag_bytes)  # Flag
        
        # Sample network traffic entries
        entries = [
            ('192.168.1.100', '10.0.0.5', 1000),
            ('192.168.1.101', '10.0.0.10', 2500),
            ('10.0.0.15', '192.168.1.200', 800),
            ('172.16.0.50', '8.8.8.8', 1200),
            ('192.168.1.100', '173.194.46.100', 3500),  # Google IP
            ('10.0.0.25', '1.1.1.1', 900),  # Cloudflare DNS
            ('192.168.1.150', '192.168.1.200', 4500),
            ('172.16.0.75', '10.0.0.100', 650),
        ]
        
        # Number of entries
        f.write(struct.pack('>I', len(entries)))
        
        # Write body entries
        base_timestamp = creation_time
        for i, (src_ip, dst_ip, bytes_transferred) in enumerate(entries):
            src_ip_int = ip_to_int(src_ip)
            dst_ip_int = ip_to_int(dst_ip)
            timestamp = base_timestamp + (i * 60)  # 1 minute apart
            
            # Write entry (16 bytes total)
            f.write(struct.pack('>I', src_ip_int))        # Source IP
            f.write(struct.pack('>I', dst_ip_int))        # Destination IP  
            f.write(struct.pack('>I', timestamp))         # Timestamp
            f.write(struct.pack('>I', bytes_transferred)) # Bytes transferred


if __name__ == '__main__':
    create_sample_sky_log('sample.sky')
    print("Created sample.sky binary log file")