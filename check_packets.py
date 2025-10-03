#!/usr/bin/env python3

"""
Check packets 4-8 to understand the HTTP flow
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_packet_content():
    """Check the content of packets around the HTTP response"""
    
    try:
        from scapy.all import rdpcap
        
        packets = rdpcap('test_data/HTTP2.pcap')
        
        for i in range(3, 8):  # Packets 4-8
            packet = packets[i]
            print(f"\n=== Packet {i+1} ===")
            
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load
                print(f"Raw data length: {len(raw_data)}")
                print(f"First 200 bytes:")
                print(repr(raw_data[:200]))
                print(f"Starts with HTTP/: {raw_data.startswith(b'HTTP/')}")
                
                # Look for HTTP boundary in the data
                if b'HTTP/' in raw_data:
                    pos = raw_data.find(b'HTTP/')
                    print(f"HTTP/ found at position: {pos}")
                    print(f"Context around HTTP/:")
                    start = max(0, pos - 50)
                    end = min(len(raw_data), pos + 300)
                    print(repr(raw_data[start:end]))
            else:
                print("No Raw layer")
                    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_packet_content()