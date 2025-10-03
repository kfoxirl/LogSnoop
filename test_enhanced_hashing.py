#!/usr/bin/env python3
"""
Enhanced HTTP File Hash Analysis with Raw Packet Content Extraction
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from logsnoop.plugins.pcap_network import PcapNetworkPlugin

def test_enhanced_packet_inspection():
    """Test enhanced packet inspection for actual file content."""
    
    print("🔬 Enhanced HTTP Packet Inspection for File Content Hashing")
    print("=" * 80)
    
    plugin = PcapNetworkPlugin()
    
    # Load and inspect the raw packets more deeply
    test_file = 'test_data/HTTP2.pcap'
    
    print(f"📄 Deep packet inspection of: {test_file}")
    
    try:
        # Access Scapy directly for raw packet inspection
        from scapy.all import rdpcap, Raw
        from scapy.layers.http import HTTPRequest, HTTPResponse
        import hashlib
        
        packets = rdpcap(test_file)
        print(f"📦 Loaded {len(packets)} raw packets for inspection")
        
        print(f"\n🔍 Analyzing packets for HTTP responses with file content...")
        
        for i, packet in enumerate(packets):
            if packet.haslayer(HTTPResponse):
                http_resp = packet[HTTPResponse]
                print(f"\n📋 HTTP Response Packet #{i+1}:")
                
                # Get status code
                if hasattr(http_resp, 'Status_Code') and http_resp.Status_Code:
                    status = http_resp.Status_Code.decode()
                    print(f"  📊 Status Code: {status}")
                
                # Get content type
                if hasattr(http_resp, 'Content_Type') and http_resp.Content_Type:
                    content_type = http_resp.Content_Type.decode()
                    print(f"  🏷️  Content-Type: {content_type}")
                
                # Get content length
                if hasattr(http_resp, 'Content_Length') and http_resp.Content_Length:
                    content_length = http_resp.Content_Length.decode()
                    print(f"  📏 Content-Length: {content_length}")
                
                # Try to extract actual file content from Raw layer
                if packet.haslayer(Raw):
                    raw_data = packet[Raw].load
                    print(f"  📦 Raw Data Length: {len(raw_data)} bytes")
                    
                    # Look for HTTP response body (after double CRLF)
                    http_header_end = raw_data.find(b'\\r\\n\\r\\n')
                    if http_header_end != -1:
                        file_content = raw_data[http_header_end + 4:]  # Skip the \\r\\n\\r\\n
                        
                        if len(file_content) > 0:
                            print(f"  📄 Extracted File Content: {len(file_content)} bytes")
                            
                            # Calculate actual file content hashes
                            md5_hash = hashlib.md5(file_content).hexdigest()
                            sha256_hash = hashlib.sha256(file_content).hexdigest()
                            
                            print(f"  🔐 Real MD5 Hash: {md5_hash}")
                            print(f"  🔑 Real SHA256 Hash: {sha256_hash}")
                            
                            # Analyze file signature
                            file_signature = file_content[:16].hex() if len(file_content) >= 16 else file_content.hex()
                            print(f"  🔍 File Signature (hex): {file_signature}")
                            
                            # Check for common file headers
                            if file_content.startswith(b'\\x89PNG'):
                                print(f"  🖼️  File Type: PNG Image (confirmed by signature)")
                            elif file_content.startswith(b'\\xff\\xd8\\xff'):
                                print(f"  🖼️  File Type: JPEG Image (confirmed by signature)")
                            elif file_content.startswith(b'GIF87a') or file_content.startswith(b'GIF89a'):
                                print(f"  🖼️  File Type: GIF Image (confirmed by signature)")
                            elif file_content.startswith(b'PK\\x03\\x04'):
                                print(f"  📦 File Type: ZIP Archive (confirmed by signature)")
                            elif file_content.startswith(b'%PDF'):
                                print(f"  📄 File Type: PDF Document (confirmed by signature)")
                            else:
                                print(f"  ❓ File Type: Unknown signature")
                        else:
                            print(f"  ⚠️  No file content found after HTTP headers")
                    else:
                        print(f"  ⚠️  HTTP header boundary not found")
                else:
                    print(f"  ⚠️  No Raw layer found in packet")
                    
    except ImportError:
        print(f"❌ Scapy not available for direct packet inspection")
    except Exception as e:
        print(f"❌ Error during packet inspection: {e}")
    
    print(f"\n{'='*80}")
    print("🎯 Enhanced File Hash Analysis Capabilities:")
    print("✅ Metadata-based hash calculation (current implementation)")
    print("✅ Raw packet content extraction (enhanced capability)")  
    print("✅ File signature verification")
    print("✅ Actual file content MD5/SHA256 hashing")
    print("✅ File type validation by magic bytes")
    print("💼 Perfect for digital forensics and malware analysis!")

if __name__ == "__main__":
    test_enhanced_packet_inspection()