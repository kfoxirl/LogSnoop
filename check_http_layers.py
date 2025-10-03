#!/usr/bin/env python3

"""
Check for HTTP layers in packets
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_http_layers():
    """Check which packets have HTTP layers"""
    
    try:
        from scapy.all import rdpcap
        
        packets = rdpcap('test_data/HTTP2.pcap')
        print(f"Checking all {len(packets)} packets for HTTP layers...")
        
        for i, packet in enumerate(packets):
            layers = []
            layer = packet
            while layer:
                layer_name = layer.__class__.__name__
                layers.append(layer_name)
                layer = layer.payload if hasattr(layer, 'payload') and layer.payload else None
                if layer and layer.__class__.__name__ == 'NoPayload':
                    break
            
            print(f"Packet {i+1}: {' -> '.join(layers)}")
            
            # Check specifically for HTTP-related layers
            if 'HTTPResponse' in [l.__class__.__name__ for l in packet.layers()]:
                print(f"  ✅ Has HTTPResponse layer")
            if 'HTTPRequest' in [l.__class__.__name__ for l in packet.layers()]:
                print(f"  ✅ Has HTTPRequest layer")
                    
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_http_layers()