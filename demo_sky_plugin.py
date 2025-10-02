#!/usr/bin/env python3
"""
SKY Plugin Demo - Demonstrates the capabilities of the SKY binary log plugin
"""

from logsnoop.core import LogParser


def demo_sky_plugin():
    """Demonstrate SKY plugin functionality."""
    
    print("="*60)
    print("LogSnoop SKY Binary Log Plugin Demo")
    print("="*60)
    
    # Initialize parser
    parser = LogParser("demo.db")
    
    print("\n1. Available Plugins:")
    plugins = parser.get_available_plugins()
    for plugin_name in plugins:
        plugin = parser.plugins[plugin_name]
        print(f"   - {plugin_name}: {plugin.description}")
    
    print(f"\n2. SKY Plugin Supported Queries:")
    sky_plugin = parser.plugins['sky_log']
    for query in sky_plugin.supported_queries:
        print(f"   - {query}")
    
    print(f"\n3. Parsing sample SKY binary file...")
    result = parser.parse_log_file("sample.sky", "sky_log")
    print(f"   Successfully parsed {result['entries_count']} entries")
    print(f"   File ID: {result['file_id']}")
    
    print(f"\n4. File Summary:")
    summary = result['summary']
    for key, value in summary.items():
        if key == 'total_bytes':
            print(f"   {key.replace('_', ' ').title()}: {value:,} bytes ({value/1024:.2f} KB)")
        elif 'timestamp' in key.lower():
            print(f"   {key.replace('_', ' ').title()}: {value}")
        else:
            print(f"   {key.replace('_', ' ').title()}: {value}")
    
    print(f"\n5. Sample Queries:")
    
    # Traffic Summary
    print(f"\n   Traffic Summary:")
    traffic_summary = parser.query_logs("sky_log", "traffic_summary")
    for key, value in traffic_summary.items():
        if key == 'total_bytes':
            print(f"     {key.replace('_', ' ').title()}: {value:,} bytes")
        elif isinstance(value, float):
            print(f"     {key.replace('_', ' ').title()}: {value:.2f}")
        else:
            print(f"     {key.replace('_', ' ').title()}: {value}")
    
    # Top Talkers by Bytes
    print(f"\n   Top Talkers (by bytes transferred):")
    top_talkers = parser.query_logs("sky_log", "top_talkers", by_bytes=True, limit=5)
    for ip, bytes_transferred in top_talkers.items():
        print(f"     {ip}: {bytes_transferred:,} bytes")
    
    # IP Pairs
    print(f"\n   Most Active IP Pairs:")
    ip_pairs = parser.query_logs("sky_log", "ip_pairs", limit=5, sort_by="bytes")
    for pair, stats in ip_pairs.items():
        print(f"     {pair}: {stats['connections']} connections, {stats['bytes']:,} bytes")
    
    # Bytes by Source
    print(f"\n   Data Sent by Source IP:")
    bytes_by_source = parser.query_logs("sky_log", "bytes_by_source")
    for ip, bytes_sent in list(bytes_by_source.items())[:5]:
        print(f"     {ip}: {bytes_sent:,} bytes")
    
    print(f"\n6. Binary File Format Details:")
    print(f"   - Magic Bytes: 0x91534B590D0A1A0A")
    print(f"   - Version: 1 (SKYv1)")
    print(f"   - Header contains: creation timestamp, hostname, flags")
    print(f"   - Each entry: source IP, destination IP, timestamp, bytes transferred")
    print(f"   - All integers stored in big-endian format")
    print(f"   - Total header + body size: {result['summary'].get('file_size', 'N/A')} bytes")
    
    print("\n" + "="*60)
    print("Demo Complete!")
    print("="*60)


if __name__ == '__main__':
    demo_sky_plugin()