#!/usr/bin/env python3
"""
Pandora Protocol - Base64 Reconstruction
"""

import base64

def reconstruct_base64_data():
    """Reconstruct the fragmented Base64 data from all encrypt requests."""
    
    print("🔍 PANDORA PROTOCOL - BASE64 RECONSTRUCTION")
    print("=" * 60)
    
    # The raw data from each encrypt request (removing newlines)
    fragments = [
        b'TkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBO\nQ0wtRkpDRy0',
        b'xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5D\nTC1GSk',
        b'NHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNM\nLUZKQ0ctMTYzMiBOQ0wtRkpDRy0xNjMyIE5D',
        b'TC1GSkNHLTE2MzIgTkNMLUZKQ0ctMTYzMiBOQ0wt\nRkpDRy0xNjMyIE5DTC1GSkNHLTE2MzIgTkNMLUZKQ0ctMT',
        b'YzMiBOQ0wtRkpDRy0xNjMyIE5DTC1G\nSkN'
    ]
    
    # Remove newlines and concatenate
    full_base64 = b''.join(fragment.replace(b'\n', b'') for fragment in fragments)
    
    print(f"📋 Reconstructed Base64 ({len(full_base64)} chars):")
    print(f"   {full_base64.decode()}")
    print()
    
    # Decode Base64
    try:
        # Add padding if needed
        padding_needed = (4 - len(full_base64) % 4) % 4
        padded_base64 = full_base64 + b'=' * padding_needed
        
        decoded_data = base64.b64decode(padded_base64)
        
        print(f"✅ Successfully decoded Base64!")
        print(f"📄 Decoded length: {len(decoded_data)} bytes")
        print(f"📝 Decoded data: {decoded_data}")
        
        # Try to interpret as text
        try:
            decoded_text = decoded_data.decode('utf-8')
            print(f"📖 Decoded text: '{decoded_text}'")
        except UnicodeDecodeError:
            print(f"❌ Not valid UTF-8 text")
            
        # Show as hex for analysis
        print(f"🔍 Hex representation: {decoded_data.hex()}")
        
        return decoded_data
        
    except Exception as e:
        print(f"❌ Base64 decode error: {e}")
        return None

def analyze_hashes():
    """Analyze the SHA-256 hashes returned by the server."""
    
    print(f"\n🔐 SERVER RESPONSE - HASH ANALYSIS")
    print("-" * 40)
    
    # The 5 SHA-256 hashes extracted from the server response
    hashes = [
        "b8c97b08e198fa9ff79a3a9c1f0109b18687b7a1a3ff1772c29b4dc86753d711",
        "8817153ae81d94b5d6c745e63d1df31d5d02bd3b030b820c3c038654fdca619c", 
        "f8f9e772e1d42c5a327c0fec4101eca5a27b6d93b1d2102db5a37ebd52e34305",
        "f5efdbdcfa80e9c0b9af155f6273ba997cbd3e4afddad2a950dfb9f786c564f7",
        "6a48c4295ef0fa5f9bfed8283a700b63fef2054686e97874096b1c2bc0d96ec4"
    ]
    
    print(f"📊 Received {len(hashes)} SHA-256 hashes:")
    for i, hash_value in enumerate(hashes, 1):
        print(f"   Hash #{i}: {hash_value}")
    
    return hashes

def create_report():
    """Generate the final Pandora protocol analysis report."""
    
    print(f"\n" + "=" * 60)
    print("📋 PANDORA'S BOX - PROTOCOL ANALYSIS REPORT")
    print("=" * 60)
    
    # Reconstruct the data
    decoded_data = reconstruct_base64_data()
    
    # Analyze hashes  
    hashes = analyze_hashes()
    
    print(f"\n📊 PROTOCOL SUMMARY:")
    print(f"   📡 Communication Stream: 10.1.0.217:42455 -> 10.1.0.20:60123")
    print(f"   📋 Initialization: 5 encrypt requests")
    print(f"   ✓ Check Value: 0x0417 (1047) - consistent across all requests")
    print(f"   🔐 Data Format: Base64-encoded fragmented across 5 requests")
    print(f"   📥 Server Response: 160 bytes containing 5 SHA-256 hashes")
    
    if decoded_data:
        print(f"\n🎯 KEY FINDINGS:")
        print(f"   📝 Decoded Message: '{decoded_data.decode('utf-8', errors='ignore')}'")
        print(f"   🔐 Message appears to be encrypted/hashed by server")
        print(f"   📊 Server returned {len(hashes)} SHA-256 hashes as requested")
    
    print(f"\n✅ PROTOCOL ANALYSIS COMPLETE!")

if __name__ == '__main__':
    create_report()