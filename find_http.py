#!/usr/bin/env python3

"""
Find the HTTP response packet
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def find_http_response():
    """Find which packet contains the HTTP response"""
    
    try:
        from scapy.all import rdpcap
        
        packets = rdpcap('test_data/HTTP2.pcap')
        print(f"Checking all {len(packets)} packets for HTTP responses...")
        
        for i, packet in enumerate(packets):
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load
                if raw_data.startswith(b'HTTP/'):
                    print(f"✅ HTTP Response found in packet {i+1}")
                    print(f"   Raw data length: {len(raw_data)}")
                    print(f"   First 200 bytes:")
                    print(f"   {raw_data[:200]}")
                    
                    # Check if it has TCP and IP layers
                    has_tcp = packet.haslayer('TCP')
                    has_ip = packet.haslayer('IP')
                    print(f"   Has TCP: {has_tcp}")
                    print(f"   Has IP: {has_ip}")
                    
                    if has_tcp and has_ip:
                        ip_layer = packet['IP']
                        tcp_layer = packet['TCP']
                        print(f"   Stream: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
                    
                    break
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    find_http_response()