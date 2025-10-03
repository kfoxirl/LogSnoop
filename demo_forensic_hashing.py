#!/usr/bin/env python3
"""
Comprehensive HTTP File Hash Analysis Demonstration
Shows full forensic capabilities for file integrity verification
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def demonstrate_forensic_capabilities():
    """Demonstrate comprehensive forensic file hash analysis capabilities."""
    
    print("🕵️  HTTP FILE HASH ANALYSIS - DIGITAL FORENSICS CAPABILITIES")
    print("=" * 90)
    
    plugin = PcapNetworkPlugin()
    
    # Test with HTTP2.pcap
    test_file = 'test_data/HTTP2.pcap'
    
    print(f"📁 Forensic Analysis of: {test_file}")
    result = plugin.parse_binary_file(test_file)
    entries = result['entries']
    print(f"📊 Evidence Base: {len(entries)} network packets processed")
    
    print(f"\n🔬 FORENSIC ANALYSIS SUITE")
    print("=" * 90)
    
    # Run all file-related analyses
    analyses = [
        ('http_file_downloads', 'Standard File Download Detection'),
        ('http_file_hashes', 'Advanced File Hash Fingerprinting'),
        ('http_security', 'Security Threat Assessment'),
        ('http_performance', 'Bandwidth and Transfer Analysis')
    ]
    
    results = {}
    
    for query_name, description in analyses:
        print(f"\n--- 🎯 {description.upper()} ---")
        try:
            result = plugin.query(query_name, entries)
            results[query_name] = result
            
            if query_name == 'http_file_downloads':
                print(f"✅ Files Detected: {result.get('total_downloads', 0)}")
                print(f"📊 Total Size: {result.get('total_download_mb', 0)} MB")
                print(f"📁 File Types: {list(result.get('downloads_by_type', {}).keys())}")
                
            elif query_name == 'http_file_hashes':
                print(f"🔐 Files with Hash Analysis: {result.get('total_downloads_with_hashes', 0)}")
                print(f"🆔 Unique MD5 Fingerprints: {result.get('unique_md5_hashes', 0)}")
                print(f"🔑 Unique SHA256 Fingerprints: {result.get('unique_sha256_hashes', 0)}")
                print(f"👥 Duplicate Detection: {result.get('duplicate_files_detected', 0)} potential duplicates")
                
            elif query_name == 'http_security':
                print(f"🛡️  Security Score: {result.get('security_score', 0)}/100")
                print(f"🚨 Suspicious Patterns: {result.get('suspicious_requests', 0)}")
                print(f"🔐 Auth Failures: {result.get('authentication_failures_401', 0)}")
                
            elif query_name == 'http_performance':
                print(f"📈 Transfer Efficiency: {result.get('avg_response_size', 0):,} bytes avg response")
                print(f"📊 Large Files (>1MB): {result.get('large_responses_1mb_plus', 0)}")
                
        except Exception as e:
            print(f"❌ Analysis Error: {e}")
    
    # Detailed forensic report
    if 'http_file_hashes' in results:
        hash_data = results['http_file_hashes']
        
        print(f"\n🗂️  DETAILED FORENSIC FILE EVIDENCE")
        print("=" * 90)
        
        files = hash_data.get('file_downloads_with_hashes', [])
        for i, file_evidence in enumerate(files, 1):
            print(f"\n📋 EVIDENCE FILE #{i}")
            print(f"  🕐 Timestamp: {file_evidence.get('timestamp', 'Unknown')}")
            print(f"  📏 File Size: {file_evidence.get('size_bytes', 0):,} bytes")
            print(f"  🏷️  MIME Type: {file_evidence.get('content_type', 'Unknown')}")
            print(f"  📂 Classification: {file_evidence.get('file_type', 'Unknown')}")
            print(f"  📊 HTTP Status: {file_evidence.get('status_code', 'Unknown')}")
            print(f"  🌐 Network Flow: {file_evidence.get('src_ip', 'Unknown')} → {file_evidence.get('dst_ip', 'Unknown')}")
            print(f"  🔐 MD5 Fingerprint: {file_evidence.get('md5_hash', 'N/A')}")
            print(f"  🔑 SHA256 Fingerprint: {file_evidence.get('sha256_hash', 'N/A')}")
            print(f"  📦 Packet Size: {file_evidence.get('packet_size', 0):,} bytes")
            
            # Forensic analysis
            size_mb = file_evidence.get('size_mb', 0)
            if size_mb > 10:
                print(f"  🚨 ALERT: Large file transfer detected ({size_mb} MB)")
            
            content_type = file_evidence.get('content_type', '')
            if 'application/octet-stream' in content_type:
                print(f"  ⚠️  WARNING: Binary executable content detected")
            elif 'zip' in content_type or 'archive' in content_type:
                print(f"  📦 INFO: Archive file detected - may contain multiple files")
            elif 'image' in content_type:
                print(f"  🖼️  INFO: Image file detected")
        
        print(f"\n🔬 HASH ANALYSIS INTELLIGENCE")
        print("=" * 90)
        
        forensic = hash_data.get('forensic_summary', {})
        hash_analysis = hash_data.get('hash_analysis', {})
        
        print(f"📊 Evidence Summary:")
        print(f"  • Total Files Analyzed: {forensic.get('total_files', 0)}")
        print(f"  • Unique File Signatures: {forensic.get('unique_file_fingerprints', 0)}")
        print(f"  • Largest Transfer: {forensic.get('largest_download_mb', 0)} MB")
        print(f"  • File Categories: {', '.join(forensic.get('file_types_detected', []))}")
        
        print(f"\n🔍 Hash Collision Analysis:")
        print(f"  • MD5 Collision Risk: {hash_analysis.get('md5_collision_potential', 0)} files")
        print(f"  • SHA256 Collision Risk: {hash_analysis.get('sha256_collision_potential', 0)} files")
        print(f"  • Hash Method: {hash_analysis.get('hash_calculation_method', 'Unknown')}")
        
    print(f"\n🎯 FORENSIC ANALYSIS CAPABILITIES SUMMARY")
    print("=" * 90)
    print("✅ File Integrity Verification: MD5 and SHA256 hash generation")
    print("✅ Duplicate File Detection: Identifies identical files by hash")
    print("✅ File Type Classification: Automatic categorization by content and headers")
    print("✅ Transfer Timeline Analysis: Chronological file movement tracking")
    print("✅ Network Flow Mapping: Source/destination IP correlation")
    print("✅ Content Security Analysis: Suspicious file pattern detection")
    print("✅ Digital Evidence Chain: Complete forensic metadata preservation")
    print("✅ Malware Investigation Ready: Hash comparison with threat intelligence")
    
    print(f"\n💼 FORENSIC USE CASES:")
    print("🔍 Data Exfiltration Investigation: Track unauthorized file transfers")
    print("🛡️  Malware Analysis: Hash comparison with known threat signatures")
    print("📊 Compliance Auditing: Verify file transfer policies and procedures")
    print("🕵️  Incident Response: Rapid file integrity verification during breaches")
    print("⚖️  Legal Evidence: Generate court-admissible file transfer records")
    print("🔐 Data Loss Prevention: Monitor sensitive file movements")
    
    print(f"\n🏆 LogSnoop HTTP Hash Analysis: Enterprise Digital Forensics Platform")

if __name__ == "__main__":
    demonstrate_forensic_capabilities()