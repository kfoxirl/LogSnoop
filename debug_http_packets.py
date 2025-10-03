#!/usr/bin/env python3
"""
Debug HTTP packet content extraction
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def debug_http_packets():
    """Debug HTTP packet content to fix hash calculation."""
    
    try:
        from scapy.all import rdpcap, Raw
        from scapy.layers.http import HTTPRequest, HTTPResponse
        import hashlib
        
        file_path = 'test_data/HTTP2.pcap'
        packets = rdpcap(file_path)
        
        print(f"Debug: HTTP Packet Analysis of {len(packets)} packets")
        print("=" * 60)
        
        for i, packet in enumerate(packets):
            print(f"\nPacket {i+1}:")
            print(f"  Layers: {[layer.name for layer in packet.layers()]}")
            
            if packet.haslayer(HTTPResponse):
                print(f"  *** HTTP RESPONSE FOUND ***")
                http_resp = packet[HTTPResponse]
                
                # Print response details
                if hasattr(http_resp, 'Status_Code') and http_resp.Status_Code:
                    status = http_resp.Status_Code.decode()
                    print(f"  Status Code: {status}")
                
                if hasattr(http_resp, 'Content_Type') and http_resp.Content_Type:
                    content_type = http_resp.Content_Type.decode()
                    print(f"  Content-Type: {content_type}")
                
                if hasattr(http_resp, 'Content_Length') and http_resp.Content_Length:
                    content_length = http_resp.Content_Length.decode()
                    print(f"  Content-Length: {content_length}")
                
                # Check for raw data
                if packet.haslayer(Raw):
                    raw_data = packet[Raw].load
                    print(f"  Raw data length: {len(raw_data)} bytes")
                    print(f"  First 100 bytes (hex): {raw_data[:100].hex()}")
                    print(f"  First 100 bytes (text): {raw_data[:100]}")
                    
                    # Look for HTTP boundary
                    boundary_pos = raw_data.find(b'\\r\\n\\r\\n')
                    print(f"  HTTP boundary at position: {boundary_pos}")
                    
                    if boundary_pos != -1:
                        response_body = raw_data[boundary_pos + 4:]
                        print(f"  Response body length: {len(response_body)} bytes")
                        
                        if len(response_body) > 0:
                            # Calculate hash of actual response body
                            md5_hash = hashlib.md5(response_body).hexdigest()
                            print(f"  REAL MD5 Hash: {md5_hash}")
                            
                            # Check file signature
                            if len(response_body) >= 8:
                                sig = response_body[:8].hex()
                                print(f"  File signature: {sig}")
                                
                                if response_body.startswith(b'\\x89PNG'):
                                    print(f"  ✓ Confirmed PNG file!")
                    else:
                        # Maybe it's all content?
                        print(f"  No HTTP boundary found, checking if entire payload is content...")
                        if len(raw_data) > 100:  # Substantial content
                            md5_hash = hashlib.md5(raw_data).hexdigest()
                            print(f"  Full payload MD5: {md5_hash}")
            
            elif packet.haslayer(HTTPRequest):
                print(f"  HTTP REQUEST")
                
            elif packet.haslayer(Raw):
                raw_data = packet[Raw].load
                if len(raw_data) > 100:  # Substantial data
                    print(f"  Raw data packet: {len(raw_data)} bytes")
                    print(f"  First 50 bytes: {raw_data[:50].hex()}")
                    
                    # Check if this might be file content continuation
                    if not raw_data.startswith(b'HTTP/'):
                        print(f"  Possible file content continuation")
    
    except ImportError as e:
        print(f"Scapy import error: {e}")
    except Exception as e:
        print(f"Debug error: {e}")

if __name__ == "__main__":
    debug_http_packets()