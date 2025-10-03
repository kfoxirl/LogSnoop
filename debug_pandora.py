#!/usr/bin/env python3
"""
Debug Pandora protocol detection
"""

import sys
from logsnoop.core import LogParser

def debug_pandora():
    parser = LogParser()
    
    # Get the parsed entries for file ID 1
    entries = parser.db.get_entries_by_file(file_id=1)
    print(f"Found {len(entries)} entries")
    
    # Check if any entries have packet_data
    packet_entries = [e for e in entries if e.get('packet_data')]
    print(f"Entries with packet_data: {len(packet_entries)}")
    
    if packet_entries:
        sample = packet_entries[0]
        print(f"Sample entry keys: {list(sample.keys())}")
        if 'packet_data' in sample:
            print(f"Packet data type: {type(sample['packet_data'])}")
    
    # Look for TCP connections on non-standard ports
    tcp_connections = set()
    for entry in entries:
        if 'src_ip' in entry and 'dst_ip' in entry and 'src_port' in entry and 'dst_port' in entry:
            if entry.get('protocol') == 'TCP':
                conn = f"{entry['src_ip']}:{entry['src_port']}->{entry['dst_ip']}:{entry['dst_port']}"
                tcp_connections.add(conn)
    
    print(f"\nFound {len(tcp_connections)} unique TCP connections:")
    for conn in sorted(tcp_connections):
        print(f"  {conn}")
    
    # Look specifically for the Pandora stream we know about
    pandora_connections = [c for c in tcp_connections if '10.1.0.217:42455' in c or '10.1.0.20:60123' in c]
    print(f"\nPandora-related connections: {pandora_connections}")

if __name__ == '__main__':
    debug_pandora()