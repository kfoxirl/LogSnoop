#!/usr/bin/env python3

"""
Compare rdpcap calls to see if there's a difference
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def compare_rdpcap():
    """Compare different rdpcap calls"""
    
    try:
        # Method 1: Direct import
        from scapy.all import rdpcap
        packets1 = rdpcap('test_data/HTTP2.pcap')
        
        # Method 2: Import within function (like the plugin)
        from scapy.all import rdpcap as scapy_rdpcap
        packets2 = scapy_rdpcap('test_data/HTTP2.pcap')
        
        print(f"Method 1 packets: {len(packets1)}")
        print(f"Method 2 packets: {len(packets2)}")
        
        for i in [5, 7]:  # Check packets 6 and 8
            p1 = packets1[i]
            p2 = packets2[i]
            
            print(f"\n=== Packet {i+1} Comparison ===")
            
            if p1.haslayer('Raw') and p2.haslayer('Raw'):
                raw1 = p1['Raw'].load
                raw2 = p2['Raw'].load
                
                print(f"Method 1 Raw length: {len(raw1)}")
                print(f"Method 2 Raw length: {len(raw2)}")
                print(f"Raw data identical: {raw1 == raw2}")
                
                print(f"Method 1 starts with: {raw1[:50]}")
                print(f"Method 2 starts with: {raw2[:50]}")
            else:
                print(f"Method 1 has Raw: {p1.haslayer('Raw')}")
                print(f"Method 2 has Raw: {p2.haslayer('Raw')}")
                    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    compare_rdpcap()