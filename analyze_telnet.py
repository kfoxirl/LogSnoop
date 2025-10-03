#!/usr/bin/env python3

"""
Analyze the Telnet.pcap file to understand its structure for implementing Telnet analysis
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def analyze_telnet_pcap():
    """Analyze the Telnet PCAP file structure"""
    
    try:
        from scapy.all import rdpcap, IP, TCP, Raw
        
        packets = rdpcap('test_data/Telnet.pcap')
        print(f"🔍 Telnet PCAP Analysis")
        print(f"Total packets: {len(packets)}")
        print("=" * 60)
        
        # Track Telnet sessions
        sessions = {}
        telnet_data = []
        
        for i, packet in enumerate(packets):
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip = packet[IP]
                tcp = packet[TCP]
                
                # Telnet typically uses port 23
                is_telnet = tcp.sport == 23 or tcp.dport == 23
                
                if is_telnet:
                    session_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                    reverse_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
                    
                    # Normalize session key (always put server first)
                    if tcp.dport == 23:  # Client to server
                        norm_key = (ip.dst, tcp.dport, ip.src, tcp.sport)
                        direction = "C->S"
                    else:  # Server to client
                        norm_key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                        direction = "S->C"
                    
                    if norm_key not in sessions:
                        sessions[norm_key] = {
                            'server_ip': norm_key[0],
                            'server_port': norm_key[1],
                            'client_ip': norm_key[2],
                            'client_port': norm_key[3],
                            'packets': [],
                            'data_packets': []
                        }
                    
                    packet_info = {
                        'packet_num': i + 1,
                        'direction': direction,
                        'timestamp': packet.time,
                        'flags': tcp.flags,
                        'seq': tcp.seq,
                        'ack': tcp.ack,
                        'has_data': packet.haslayer(Raw)
                    }
                    
                    if packet.haslayer(Raw):
                        raw_data = packet[Raw].load
                        packet_info['data'] = raw_data
                        packet_info['data_len'] = len(raw_data)
                        packet_info['printable'] = raw_data.decode('utf-8', errors='replace')
                        
                        sessions[norm_key]['data_packets'].append(packet_info)
                    
                    sessions[norm_key]['packets'].append(packet_info)
        
        # Analyze sessions
        print(f"📊 Found {len(sessions)} Telnet session(s)")
        
        for i, (session_key, session) in enumerate(sessions.items()):
            print(f"\n🔗 Session {i+1}: {session['client_ip']}:{session['client_port']} <-> {session['server_ip']}:{session['server_port']}")
            print(f"   Total packets: {len(session['packets'])}")
            print(f"   Data packets: {len(session['data_packets'])}")
            
            # Show some sample data
            if session['data_packets']:
                print(f"\n📝 Sample Telnet Communication:")
                for j, data_packet in enumerate(session['data_packets'][:10]):  # First 10 data packets
                    data = data_packet['printable'].strip()
                    if data:
                        direction_symbol = "👤" if data_packet['direction'] == "C->S" else "🖥️"
                        print(f"   {direction_symbol} [{data_packet['direction']}] Packet {data_packet['packet_num']}: '{data}'")
                
                if len(session['data_packets']) > 10:
                    print(f"   ... and {len(session['data_packets']) - 10} more data packets")
                
                # Look for authentication patterns
                auth_data = []
                commands = []
                
                for data_packet in session['data_packets']:
                    data = data_packet['printable'].strip()
                    if 'login:' in data.lower() or 'password:' in data.lower():
                        auth_data.append((data_packet['direction'], data))
                    elif data_packet['direction'] == "C->S" and len(data) > 0 and data not in ['\r\n', '\n', '\r']:
                        commands.append(data)
                
                if auth_data:
                    print(f"\n🔐 Authentication Events:")
                    for direction, data in auth_data:
                        direction_symbol = "👤" if direction == "C->S" else "🖥️"
                        print(f"   {direction_symbol} {data}")
                
                if commands:
                    print(f"\n⌨️ Commands Executed:")
                    for cmd in commands[:10]:  # First 10 commands
                        if cmd and len(cmd.strip()) > 0:
                            print(f"   📋 {repr(cmd)}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    analyze_telnet_pcap()