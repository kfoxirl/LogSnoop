#!/usr/bin/env python3

"""
Analyze packet 6 in detail to see the HTTP header boundary
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def analyze_packet_6():
    """Analyze packet 6 in detail"""
    
    try:
        from scapy.all import rdpcap
        
        packets = rdpcap('test_data/HTTP2.pcap')
        packet = packets[5]  # Packet 6 (0-indexed)
        
        print(f"=== Packet 6 Analysis ===")
        
        if packet.haslayer('Raw'):
            raw_data = packet['Raw'].load
            print(f"Total Raw data length: {len(raw_data)}")
            
            # Find the HTTP header boundary
            header_end = raw_data.find(b'\r\n\r\n')
            print(f"HTTP header boundary at: {header_end}")
            
            if header_end != -1:
                headers = raw_data[:header_end]
                content_start = header_end + 4
                content = raw_data[content_start:]
                
                print(f"Headers ({len(headers)} bytes):")
                print(headers.decode('utf-8', errors='ignore'))
                print(f"\nContent starts at byte {content_start}")
                print(f"Content length: {len(content)} bytes")
                print(f"Content signature: {content[:16].hex()}")
                
                # Check if it's PNG
                if content.startswith(b'\x89PNG'):
                    print("✅ Content is PNG file")
                    import hashlib
                    print(f"Content MD5 (partial): {hashlib.md5(content).hexdigest()}")
                else:
                    print("❓ Content type unclear")
                    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    analyze_packet_6()