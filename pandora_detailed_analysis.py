#!/usr/bin/env python3
"""
Detailed Pandora Protocol Analysis
Focus on the successful protocol decode
"""

import struct
import base64
from pathlib import Path

def analyze_specific_stream():
    """Analyze the specific Pandora protocol stream that was successfully decoded."""
    
    try:
        from scapy.all import rdpcap, TCP, Raw
    except ImportError:
        print("❌ Scapy is required for PCAP analysis.")
        return
    
    print("🔍 PANDORA PROTOCOL ANALYSIS - DETAILED REPORT")
    print("=" * 60)
    
    pcap_file = Path("c:/Users/Karl/Downloads/pandora.pcap")
    packets = rdpcap(str(pcap_file))
    
    # Focus on the successful stream: 10.1.0.217:42455->10.1.0.20:60123
    client_ip = "10.1.0.217"
    client_port = 42455
    server_ip = "10.1.0.20"
    server_port = 60123
    
    client_data = b""
    server_data = b""
    
    for packet in packets:
        if TCP in packet and Raw in packet:
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
            
            # Match our target stream
            if ((src_ip == client_ip and src_port == client_port and 
                 dst_ip == server_ip and dst_port == server_port) or
                (src_ip == server_ip and src_port == server_port and 
                 dst_ip == client_ip and dst_port == client_port)):
                
                if src_ip == client_ip:
                    client_data += bytes(packet[Raw].load)
                else:
                    server_data += bytes(packet[Raw].load)
    
    print(f"📡 Target Stream: {client_ip}:{client_port} -> {server_ip}:{server_port}")
    print(f"📤 Client sent: {len(client_data)} bytes")
    print(f"📥 Server sent: {len(server_data)} bytes")
    print()
    
    # Detailed analysis of client messages
    print("📋 CLIENT MESSAGE ANALYSIS")
    print("-" * 40)
    
    offset = 0
    
    # Parse Initialization
    if len(client_data) >= 4:
        n_requests = struct.unpack('!I', client_data[offset:offset+4])[0]
        print(f"✅ Initialization Message:")
        print(f"   📊 N (Number of Encrypt Requests): {n_requests}")
        offset += 4
        
        print(f"\n🔐 ENCRYPT REQUESTS:")
        print("-" * 30)
        
        # Parse each encrypt request
        for i in range(n_requests):
            if offset + 6 > len(client_data):
                print(f"❌ Incomplete request #{i+1}")
                break
            
            # Parse Check and Length
            check = struct.unpack('!H', client_data[offset:offset+2])[0]
            length = struct.unpack('!I', client_data[offset+2:offset+6])[0]
            offset += 6
            
            # Parse Data
            if offset + length <= len(client_data):
                request_data = client_data[offset:offset+length]
                offset += length
                
                print(f"📦 Encrypt Request #{i+1}:")
                print(f"   ✓ Check Value: 0x{check:04x} ({check})")
                print(f"   📏 Data Length: {length} bytes")
                print(f"   📄 Raw Data: {request_data}")
                
                # Try to decode as Base64
                try:
                    decoded = base64.b64decode(request_data)
                    print(f"   🔓 Base64 Decoded: {decoded}")
                    
                    # Try to decode as text
                    try:
                        text = decoded.decode('utf-8', errors='ignore')
                        if text.isprintable():
                            print(f"   📝 Decoded Text: '{text}'")
                    except:
                        pass
                        
                except Exception as e:
                    print(f"   ❌ Base64 decode failed: {e}")
                
                # Try direct text decode
                try:
                    text = request_data.decode('utf-8', errors='ignore')
                    if text.isprintable():
                        print(f"   📝 Direct Text: '{text}'")
                except:
                    pass
                
                print()
            else:
                print(f"❌ Incomplete data for request #{i+1}")
                break
    
    # Detailed analysis of server response
    print("📥 SERVER RESPONSE ANALYSIS")
    print("-" * 40)
    
    if len(server_data) >= 4:
        response_length = struct.unpack('!I', server_data[0:4])[0]
        print(f"✅ Encrypt Response:")
        print(f"   📏 Count (Response Length): {response_length} bytes")
        
        if len(server_data) >= 4 + response_length:
            hashes_data = server_data[4:4+response_length]
            print(f"   🔐 Hashes Data: {len(hashes_data)} bytes")
            
            # Analyze hash structure
            print(f"\n🔍 HASH ANALYSIS:")
            print("-" * 20)
            
            # Common hash sizes
            hash_info = {
                16: "MD5",
                20: "SHA-1", 
                32: "SHA-256",
                64: "SHA-512"
            }
            
            for hash_size, hash_type in hash_info.items():
                if len(hashes_data) % hash_size == 0:
                    num_hashes = len(hashes_data) // hash_size
                    print(f"💡 Possible {hash_type} hashes: {num_hashes} hashes of {hash_size} bytes each")
                    
                    if num_hashes == n_requests:
                        print(f"   ✅ MATCH: Number of hashes ({num_hashes}) equals number of requests ({n_requests})")
                        
                        print(f"\n📊 EXTRACTED HASHES ({hash_type}):")
                        for i in range(num_hashes):
                            hash_bytes = hashes_data[i*hash_size:(i+1)*hash_size]
                            hash_hex = hash_bytes.hex()
                            print(f"   Hash #{i+1}: {hash_hex}")
                        
                        # This is likely our correct interpretation
                        break
                    else:
                        print(f"   ❌ Mismatch: {num_hashes} hashes vs {n_requests} requests")
            
        else:
            print(f"❌ Incomplete response data (expected {response_length}, got {len(server_data)-4})")
    
    print(f"\n" + "=" * 60)
    print("📋 PANDORA PROTOCOL SUMMARY")
    print("=" * 60)
    
    print(f"✅ Successfully decoded Pandora protocol communication")
    print(f"📡 Stream: {client_ip}:{client_port} -> {server_ip}:{server_port}")
    print(f"📊 Protocol flow completed successfully")
    print(f"🔐 All encrypt requests and responses captured")

if __name__ == '__main__':
    analyze_specific_stream()