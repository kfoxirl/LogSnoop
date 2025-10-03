#!/usr/bin/env python3
"""
Test HTTP File Hash Analysis functionality
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def test_http_file_hashes():
    """Test the HTTP file hash analysis functionality."""
    
    print("🔐 Testing HTTP File Hash Analysis with Forensic Capabilities")
    print("=" * 85)
    
    plugin = PcapNetworkPlugin()
    
    # Load the HTTP2.pcap file
    test_file = 'test_data/HTTP2.pcap'
    
    if not os.path.exists(test_file):
        print(f"❌ Test file {test_file} not found.")
        return
    
    print(f"📄 Loading PCAP file: {test_file}")
    result = plugin.parse_binary_file(test_file)
    entries = result['entries']
    print(f"📊 Loaded {len(entries)} packet entries")
    
    print(f"\n🔍 Running HTTP File Hash Analysis...")
    print("=" * 85)
    
    try:
        hash_result = plugin.query('http_file_hashes', entries)
        
        print(f"📋 FILE DOWNLOAD HASH ANALYSIS RESULTS:")
        print(f"  🗂️  Total Downloads with Hashes: {hash_result.get('total_downloads_with_hashes', 0)}")
        print(f"  💾 Total Download Size: {hash_result.get('total_download_mb', 0)} MB")
        print(f"  🔐 Unique MD5 Hashes: {hash_result.get('unique_md5_hashes', 0)}")
        print(f"  🔑 Unique SHA256 Hashes: {hash_result.get('unique_sha256_hashes', 0)}")
        print(f"  👥 Potential Duplicates: {hash_result.get('duplicate_files_detected', 0)}")
        
        print(f"\n📁 File Type Breakdown:")
        for file_type, count in hash_result.get('downloads_by_type', {}).items():
            print(f"  {file_type}: {count} files")
        
        print(f"\n🗃️  Detailed File Download Analysis:")
        downloads = hash_result.get('file_downloads_with_hashes', [])
        
        for i, download in enumerate(downloads, 1):
            print(f"\n  📁 File #{i}:")
            print(f"    📅 Timestamp: {download.get('timestamp', 'N/A')}")
            print(f"    📏 Size: {download.get('size_bytes', 0):,} bytes ({download.get('size_mb', 0)} MB)")
            print(f"    🏷️  Type: {download.get('file_type', 'unknown')}")
            print(f"    📋 Content-Type: {download.get('content_type', 'N/A')}")
            print(f"    📊 Status Code: {download.get('status_code', 'N/A')}")
            print(f"    🌐 Source: {download.get('src_ip', 'N/A')} -> {download.get('dst_ip', 'N/A')}")
            print(f"    🔐 MD5 Hash: {download.get('md5_hash', 'N/A')}")
            print(f"    🔑 SHA256 Hash: {download.get('sha256_hash', 'N/A')}")
            print(f"    ℹ️  Note: {download.get('hash_note', '')}")
        
        print(f"\n🔬 Hash Analysis Details:")
        hash_analysis = hash_result.get('hash_analysis', {})
        print(f"  🔍 MD5 Collision Potential: {hash_analysis.get('md5_collision_potential', 0)}")
        print(f"  🔍 SHA256 Collision Potential: {hash_analysis.get('sha256_collision_potential', 0)}")
        print(f"  ⚙️  Method: {hash_analysis.get('hash_calculation_method', 'N/A')}")
        
        print(f"\n🕵️  Forensic Summary:")
        forensic = hash_result.get('forensic_summary', {})
        print(f"  📊 Total Files: {forensic.get('total_files', 0)}")
        print(f"  🆔 Unique Fingerprints: {forensic.get('unique_file_fingerprints', 0)}")
        print(f"  📈 Largest Download: {forensic.get('largest_download_mb', 0)} MB")
        print(f"  🗂️  File Types: {', '.join(forensic.get('file_types_detected', []))}")
        
        # Check if there are duplicates
        duplicates = hash_result.get('potential_duplicates', [])
        if duplicates:
            print(f"\n⚠️  POTENTIAL DUPLICATE FILES DETECTED:")
            for i, dup in enumerate(duplicates[:5], 1):
                print(f"    {i}. {dup.get('content_type', 'unknown')} - MD5: {dup.get('md5_hash', 'N/A')[:16]}...")
        
        print(f"\n💡 Analysis Result: {hash_result.get('analysis', 'Analysis completed')}")
        
    except Exception as e:
        print(f"❌ Error during hash analysis: {e}")
    
    print(f"\n{'='*85}")
    print("🎉 HTTP File Hash Analysis Complete!")
    print("✨ Forensic file integrity and duplicate detection capabilities demonstrated.")
    
    # Compare with regular file downloads
    print(f"\n📊 Comparing with Standard File Downloads Analysis:")
    try:
        regular_downloads = plugin.query('http_file_downloads', entries)
        print(f"  📥 Regular Analysis: {regular_downloads.get('total_downloads', 0)} downloads")
        print(f"  🔐 Hash Analysis: {hash_result.get('total_downloads_with_hashes', 0)} downloads with hashes")
        print(f"  💼 Enhanced forensic capabilities: MD5/SHA256 fingerprinting for file identification")
    except Exception as e:
        print(f"  ❌ Comparison error: {e}")

if __name__ == "__main__":
    test_http_file_hashes()