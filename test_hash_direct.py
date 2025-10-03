#!/usr/bin/env python3

"""
Direct test of HTTP hash functionality using the correct approach
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def test_http_hash_direct():
    """Test the HTTP hash functionality directly"""
    
    print("🔐 Direct HTTP Hash Test")
    print("=" * 50)
    
    # Initialize plugin
    plugin = PcapNetworkPlugin()
    
    # Parse the PCAP file
    parse_result = plugin.parse_binary_file('test_data/HTTP2.pcap')
    entries = parse_result.get('entries', [])
    
    print(f"📊 Parsed {len(entries)} entries")
    
    # Test the hash query with file path parameter
    result = plugin.query('http_file_hashes', entries, file_path='test_data/HTTP2.pcap')
    
    print(f"\n🔍 Hash Query Results:")
    print(f"  Status: {'Success' if 'error' not in result else 'Error'}")
    
    if 'error' in result:
        print(f"  Error: {result['error']}")
    else:
        print(f"  Total files with hashes: {result.get('total_downloads_with_hashes', 0)}")
        
        if 'file_downloads_with_hashes' in result and result['file_downloads_with_hashes']:
            for i, download in enumerate(result['file_downloads_with_hashes']):
                print(f"\n  📁 File {i+1}:")
                print(f"    Size: {download.get('size_bytes', 0)} bytes")
                print(f"    Type: {download.get('content_type', 'unknown')}")
                print(f"    MD5: {download.get('md5_hash', 'N/A')}")
                print(f"    SHA256: {download.get('sha256_hash', 'N/A')}")
                print(f"    Signature: {download.get('file_signature', 'N/A')}")

if __name__ == "__main__":
    test_http_hash_direct()