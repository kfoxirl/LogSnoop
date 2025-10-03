#!/usr/bin/env python3

"""
Debug HTTP file hash extraction to understand why we're getting 0 files
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import rdpcap, IP, TCP, Raw
from datetime import datetime
import hashlib

def debug_hash_extraction():
    """Debug the HTTP file hash extraction process"""
    
    file_path = 'test_data/HTTP2.pcap'
    packets = rdpcap(file_path)
    
    print(f"Debug: HTTP File Hash Extraction")
    print(f"Total packets: {len(packets)}")
    print("=" * 60)
    
    file_transfers = {}
    
    for i, packet in enumerate(packets):
        if not packet.haslayer(Raw):
            continue
            
        raw_data = packet[Raw].load
        
        # Check for HTTP response headers
        if raw_data.startswith(b'HTTP/'):
            print(f"\n🔍 HTTP Response found in packet {i+1}")
            header_end = raw_data.find(b'\r\n\r\n')
            print(f"Header boundary at position: {header_end}")
            
            if header_end == -1:
                print("  ❌ No header boundary found, skipping")
                continue
                
            headers_text = raw_data[:header_end].decode('utf-8', errors='ignore')
            content_start = header_end + 4
            
            print(f"Headers:\n{headers_text}")
            print(f"Content starts at byte: {content_start}")
            print(f"Remaining data length: {len(raw_data) - content_start}")
            
            # Parse response info
            response_info = {}
            for line in headers_text.split('\r\n'):
                if line.startswith('HTTP/'):
                    parts = line.split()
                    if len(parts) >= 2:
                        response_info['status_code'] = parts[1]
                elif line.lower().startswith('content-type:'):
                    response_info['content_type'] = line.split(':', 1)[1].strip()
                elif line.lower().startswith('content-length:'):
                    try:
                        response_info['content_length'] = int(line.split(':', 1)[1].strip())
                    except ValueError:
                        pass
            
            print(f"Parsed response info: {response_info}")
            
            # Check if this meets our criteria
            if (response_info.get('status_code') == '200' and 
                'content_length' in response_info and
                'content_type' in response_info):
                
                content_type = response_info['content_type'].lower()
                print(f"Content type (lowercase): {content_type}")
                
                # Check if it's a file we want to process
                file_types = ['image/', 'application/', 'video/', 'audio/']
                matches = [ftype for ftype in file_types if ftype in content_type]
                print(f"File type matches: {matches}")
                
                if matches:
                    if packet.haslayer(TCP) and packet.haslayer(IP):
                        stream_key = (packet[IP].src, packet[TCP].sport,
                                     packet[IP].dst, packet[TCP].dport)
                        print(f"Stream key: {stream_key}")
                        
                        initial_content = raw_data[content_start:]
                        print(f"Initial content length: {len(initial_content)}")
                        print(f"Expected total size: {response_info['content_length']}")
                        
                        file_transfers[stream_key] = {
                            'info': response_info,
                            'timestamp': packet.time,
                            'content': initial_content,
                            'expected_size': response_info['content_length']
                        }
                        print(f"✅ File transfer registered for stream {stream_key}")
                    else:
                        print("❌ Packet missing TCP or IP layers")
                else:
                    print(f"❌ Content type '{content_type}' doesn't match file criteria")
            else:
                print(f"❌ Response doesn't meet criteria:")
                print(f"    Status: {response_info.get('status_code', 'missing')}")
                print(f"    Content-Length: {'present' if 'content_length' in response_info else 'missing'}")
                print(f"    Content-Type: {'present' if 'content_type' in response_info else 'missing'}")
        
        # Check for continuation packets
        elif packet.haslayer(TCP) and packet.haslayer(IP):
            stream_key = (packet[IP].src, packet[TCP].sport,
                         packet[IP].dst, packet[TCP].dport)
            
            if stream_key in file_transfers:
                transfer = file_transfers[stream_key]
                if len(transfer['content']) < transfer['expected_size']:
                    print(f"📎 Adding {len(raw_data)} bytes to transfer for stream {stream_key}")
                    transfer['content'] += raw_data
                    print(f"   Total content now: {len(transfer['content'])}/{transfer['expected_size']} bytes")
    
    # Process completed transfers
    print(f"\n🔬 Processing {len(file_transfers)} file transfers:")
    for stream_key, transfer in file_transfers.items():
        content = transfer['content']
        expected_size = transfer['expected_size']
        
        print(f"\nStream {stream_key}:")
        print(f"  Content size: {len(content)} bytes")
        print(f"  Expected size: {expected_size} bytes")
        print(f"  Complete: {len(content) >= expected_size}")
        
        if len(content) >= expected_size:
            content = content[:expected_size]
            md5_hash = hashlib.md5(content).hexdigest()
            print(f"  🔐 MD5 Hash: {md5_hash}")
            print(f"  🔍 File signature: {content[:16].hex()}")
            
            # Check PNG signature
            if content.startswith(b'\x89PNG'):
                print(f"  ✅ Confirmed PNG file!")
            else:
                print(f"  ❓ File type unclear from signature")

if __name__ == "__main__":
    debug_hash_extraction()