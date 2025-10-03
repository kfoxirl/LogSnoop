#!/usr/bin/env python3
"""
Pandora Protocol Analyzer
Analyzes the custom protocol described in the documentation
"""

import struct
import sys
from pathlib import Path

def analyze_pandora_protocol(pcap_file):
    """Analyze Pandora's Box custom protocol from PCAP file."""
    
    try:
        from scapy.all import rdpcap, TCP, Raw
    except ImportError:
        print("❌ Scapy is required for PCAP analysis.")
        print("📦 Install with: pip install scapy")
        return
    
    print(f"🔍 Analyzing Pandora protocol in: {pcap_file}")
    print("=" * 60)
    
    # Load PCAP file
    try:
        packets = rdpcap(str(pcap_file))
        print(f"📦 Loaded {len(packets)} packets")
    except Exception as e:
        print(f"❌ Error loading PCAP: {e}")
        return
    
    # Find TCP streams with data
    tcp_streams = {}
    
    for packet in packets:
        if TCP in packet and Raw in packet:
            # Create stream identifier
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
            
            # Normalize stream direction
            if src_port < dst_port:
                stream_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                direction = "C->S"
            else:
                stream_id = f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
                direction = "S->C"
            
            if stream_id not in tcp_streams:
                tcp_streams[stream_id] = []
            
            tcp_streams[stream_id].append({
                'direction': direction,
                'data': bytes(packet[Raw].load),
                'timestamp': packet.time,
                'seq': packet['TCP'].seq,
                'ack': packet['TCP'].ack
            })
    
    print(f"🔗 Found {len(tcp_streams)} TCP streams")
    
    # Analyze each stream for Pandora protocol
    for stream_id, stream_packets in tcp_streams.items():
        print(f"\n📡 Stream: {stream_id}")
        print("-" * 50)
        
        # Sort packets by timestamp
        stream_packets.sort(key=lambda x: x['timestamp'])
        
        # Reconstruct data streams
        client_data = b""
        server_data = b""
        
        for packet in stream_packets:
            if packet['direction'] == "C->S":
                client_data += packet['data']
            else:
                server_data += packet['data']
        
        print(f"📤 Client data: {len(client_data)} bytes")
        print(f"📥 Server data: {len(server_data)} bytes")
        
        if len(client_data) > 0:
            analyze_client_messages(client_data)
        
        if len(server_data) > 0:
            analyze_server_messages(server_data)

def analyze_client_messages(data):
    """Analyze client messages according to Pandora protocol."""
    print("\n🔍 Client Message Analysis:")
    
    offset = 0
    
    # Parse Initialization message (first 4 bytes)
    if len(data) >= 4:
        n_requests = struct.unpack('!I', data[offset:offset+4])[0]
        print(f"   📋 Initialization: N = {n_requests} encrypt requests")
        offset += 4
        
        # Parse Encrypt Requests
        request_count = 0
        while offset < len(data) and request_count < n_requests:
            if offset + 6 > len(data):
                break
                
            # Parse Check (2 bytes) and Len (4 bytes)
            check = struct.unpack('!H', data[offset:offset+2])[0]
            length = struct.unpack('!I', data[offset+2:offset+6])[0]
            offset += 6
            
            # Parse Data
            if offset + length <= len(data):
                request_data = data[offset:offset+length]
                offset += length
                request_count += 1
                
                print(f"   🔐 Encrypt Request #{request_count}:")
                print(f"      ✓ Check: 0x{check:04x}")
                print(f"      📏 Length: {length} bytes")
                print(f"      📄 Data: {request_data[:50]}{'...' if len(request_data) > 50 else ''}")
                
                # Try to decode as text if possible
                try:
                    text = request_data.decode('utf-8', errors='ignore')
                    if text.isprintable():
                        print(f"      📝 Text: {text[:100]}{'...' if len(text) > 100 else ''}")
                except:
                    pass
            else:
                print(f"   ❌ Incomplete request data at offset {offset}")
                break
    
    if offset < len(data):
        print(f"   ℹ️  Remaining data: {len(data) - offset} bytes")

def analyze_server_messages(data):
    """Analyze server messages according to Pandora protocol."""
    print("\n🔍 Server Message Analysis:")
    
    offset = 0
    
    # Parse response length (first part)
    if len(data) >= 4:
        response_length = struct.unpack('!I', data[offset:offset+4])[0]
        print(f"   📏 Response Length: {response_length} bytes")
        offset += 4
        
        # Parse hashes
        if offset + response_length <= len(data):
            hashes_data = data[offset:offset+response_length]
            print(f"   🔐 Encrypted Hashes: {len(hashes_data)} bytes")
            
            # Try to identify hash chunks (common hash sizes: 16, 20, 32, 64 bytes)
            hash_sizes = [16, 20, 32, 64]  # MD5, SHA1, SHA256, SHA512
            
            for hash_size in hash_sizes:
                if len(hashes_data) % hash_size == 0:
                    num_hashes = len(hashes_data) // hash_size
                    print(f"   💡 Possible interpretation: {num_hashes} hashes of {hash_size} bytes each")
                    
                    # Show first few hashes
                    for i in range(min(3, num_hashes)):
                        hash_bytes = hashes_data[i*hash_size:(i+1)*hash_size]
                        hash_hex = hash_bytes.hex()
                        print(f"      Hash #{i+1}: {hash_hex}")
                    
                    if num_hashes > 3:
                        print(f"      ... and {num_hashes - 3} more hashes")
                    break
            
            offset += response_length
        else:
            print(f"   ❌ Incomplete response data")
    
    if offset < len(data):
        print(f"   ℹ️  Remaining data: {len(data) - offset} bytes")

def main():
    pcap_file = Path("c:/Users/Karl/Downloads/pandora.pcap")
    
    if not pcap_file.exists():
        print(f"❌ PCAP file not found: {pcap_file}")
        return
    
    analyze_pandora_protocol(pcap_file)

if __name__ == '__main__':
    main()