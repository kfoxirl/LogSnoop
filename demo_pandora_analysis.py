#!/usr/bin/env python3
"""
Pandora Protocol Analysis Demo
Showcases the new Pandora analysis capability in LogSnoop
"""

from logsnoop.core import LogParser

def demo_pandora_analysis():
    """Demonstrate Pandora protocol analysis capabilities."""
    
    print("=" * 70)
    print("🔍 PANDORA PROTOCOL ANALYSIS DEMO")
    print("=" * 70)
    print()
    print("This demo showcases LogSnoop's new capability to analyze")
    print("the custom Pandora encryption protocol from PCAP files.")
    print()
    
    try:
        # Initialize LogSnoop
        parser = LogParser()
        
        # Query Pandora analysis for file ID 1 (our parsed pandora.pcap)
        print("🚀 Running Pandora protocol analysis...")
        
        # Get the plugin and entries directly
        from logsnoop.plugins.pcap_network import PcapNetworkPlugin
        plugin = PcapNetworkPlugin()
        entries = parser.db.get_entries_by_file(1)
        
        result = plugin.query("pandora_analysis", entries)
        
        if result.get('pandora_protocol_detected'):
            print("✅ Pandora protocol detected and successfully decoded!")
            print()
            
            # Display key findings using the quick_reference
            ref = result['quick_reference']
            details = result['communication_details']
            
            print("🎯 QUICK REFERENCE ANSWERS:")
            print("-" * 40)
            print(f"📡 Server IP Address: {ref['server_ip']}")
            print(f"🔢 Magic 2-byte ID (decimal): {ref['magic_2byte_id_decimal']}")
            print(f"📏 First request length: {ref['first_request_length_bytes']} bytes")
            print(f"📏 Second request length: {ref['second_request_length_bytes']} bytes") 
            print(f"🔐 Individual hash size: {ref['individual_hash_size_bytes']} bytes")
            print()
            
            print("🔑 ENCRYPT RESPONSE HASHES:")
            print("-" * 40)
            print(f"1st hash: {ref['first_hash']}")
            print(f"2nd hash: {ref['second_hash']}")
            print()
            
            print("📝 DECODED MESSAGE:")
            print("-" * 40)
            decoded_msg = ref['decoded_message']
            if len(decoded_msg) > 100:
                print(f"'{decoded_msg[:100]}...'")
            else:
                print(f"'{decoded_msg}'")
            print()
            
            print("📊 PROTOCOL DETAILS:")
            print("-" * 40)
            init = details['initialization']
            encrypt_resp = details['encrypt_response']
            
            print(f"🔗 Communication: {details['client_ip']}:{details['client_port']} → {details['server_ip']}:{details['server_port']}")
            print(f"📋 Initialization: {init['number_of_encrypt_requests']} encrypt requests")
            print(f"✓ Magic Check Value: {details['magic_check_value_hex']} ({details['magic_check_value_decimal']})")
            print(f"🔐 Hash Algorithm: {encrypt_resp['hash_algorithm']}")
            print(f"📊 Total Response: {encrypt_resp['response_length_bytes']} bytes")
            print(f"🔢 Number of Hashes: {encrypt_resp['number_of_hashes']}")
            print()
            
            print("✨ ALL QUESTIONS ANSWERED!")
            print("-" * 40)
            print("The new pandora_analysis query provides instant answers to:")
            print("• What is the IP address of the server?") 
            print("• What is the magic 2-byte ID in decimal representation?")
            print("• What is the length of the first/second encrypt request?")
            print("• How large is an individual encrypt hash?")
            print("• What are the encrypt response hashes?")
            print("• What was the decoded message?")
            
        else:
            print("❌ No Pandora protocol detected")
            if 'error' in result:
                print(f"Error: {result['error']}")
        
        print()
        print("=" * 70)
        print("✅ Pandora Analysis Demo Complete!")
        print("=" * 70)
        print()
        print("💡 Usage:")
        print("   python cli.py query pcap_network pandora_analysis --file-id <id>")
        print()
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    demo_pandora_analysis()