#!/usr/bin/env python3

"""
Test basic rdpcap functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_rdpcap():
    """Test if rdpcap works at all"""
    
    try:
        from scapy.all import rdpcap
        
        print("✓ Scapy import successful")
        
        packets = rdpcap('test_data/HTTP2.pcap')
        print(f"✓ rdpcap successful, loaded {len(packets)} packets")
        
        for i, packet in enumerate(packets[:5]):  # Check first 5 packets
            print(f"Packet {i+1}:")
            print(f"  Type: {type(packet)}")
            print(f"  Has Raw: {packet.haslayer('Raw')}")
            if packet.haslayer('Raw'):
                raw_data = packet['Raw'].load
                print(f"  Raw data length: {len(raw_data)}")
                print(f"  Starts with HTTP: {raw_data.startswith(b'HTTP/')}")
                if raw_data.startswith(b'HTTP/'):
                    print(f"  First 100 bytes: {raw_data[:100]}")
            print()
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    test_rdpcap()