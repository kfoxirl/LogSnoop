#!/usr/bin/env python3
"""
Quick FTP File Size Calculator
Manually calculates correct file sizes from your PCAP file
"""

from scapy.all import rdpcap, TCP, Raw

def calculate_ftp_file_sizes():
    """Calculate the real FTP file sizes from the PCAP."""
    
    packets = rdpcap('test_data/FTP.pcap')
    
    print("🎯 Real FTP File Size Analysis")
    print("=" * 50)
    
    # Track data transfers by direction and time
    upload_data = []  # Client to server (port 20)
    download_data = []  # Server to client (port 20)
    
    for i, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            payload_size = len(pkt[Raw].load)
            
            if tcp.sport == 20:
                # Server to client = download
                download_data.append({
                    'packet': i+1,
                    'timestamp': pkt.time,
                    'size': payload_size
                })
            elif tcp.dport == 20:
                # Client to server = upload  
                upload_data.append({
                    'packet': i+1,
                    'timestamp': pkt.time,
                    'size': payload_size
                })
    
    # Calculate totals
    total_upload = sum(d['size'] for d in upload_data)
    total_download = sum(d['size'] for d in download_data)
    
    print(f"📤 UPLOAD ANALYSIS:")
    print(f"   Packets: {len(upload_data)}")
    print(f"   Total bytes: {total_upload:,} bytes")
    if upload_data:
        print(f"   First packet: {upload_data[0]['packet']} at {upload_data[0]['timestamp']}")
        print(f"   Last packet: {upload_data[-1]['packet']} at {upload_data[-1]['timestamp']}")
    
    print(f"\n📥 DOWNLOAD ANALYSIS:")
    print(f"   Packets: {len(download_data)}")
    print(f"   Total bytes: {total_download:,} bytes")
    if download_data:
        print(f"   First packet: {download_data[0]['packet']} at {download_data[0]['timestamp']}")
        print(f"   Last packet: {download_data[-1]['packet']} at {download_data[-1]['timestamp']}")
    
    print(f"\n🎯 CORRECTED FTP ANALYSIS:")
    print(f"   compcodes.zip upload: ~{total_upload:,} bytes (not 87 bytes!)")
    print(f"   compcodes.zip download: ~{total_download:,} bytes (not 87 bytes!)")
    print(f"   Total data transferred: {total_upload + total_download:,} bytes")
    
    # Look for file boundaries by analyzing timing
    print(f"\n⏱️  TRANSFER TIMING ANALYSIS:")
    
    # Group uploads by time gaps (files are separated by gaps)
    if upload_data:
        print(f"   Upload packets timing:")
        prev_time = upload_data[0]['timestamp']
        file_start = 0
        for i, data in enumerate(upload_data[1:], 1):
            gap = data['timestamp'] - prev_time
            if gap > 1.0:  # 1 second gap indicates new file
                upload_size = sum(d['size'] for d in upload_data[file_start:i])
                print(f"     File {file_start//19 + 1}: packets {file_start+1}-{i}, {upload_size:,} bytes")
                file_start = i
            prev_time = data['timestamp']
        
        # Last file
        upload_size = sum(d['size'] for d in upload_data[file_start:])
        print(f"     File {file_start//19 + 1}: packets {file_start+1}-{len(upload_data)}, {upload_size:,} bytes")
    
    if download_data:
        print(f"   Download packets timing:")
        prev_time = download_data[0]['timestamp']  
        file_start = 0
        for i, data in enumerate(download_data[1:], 1):
            gap = data['timestamp'] - prev_time
            if gap > 1.0:  # 1 second gap indicates new file
                download_size = sum(d['size'] for d in download_data[file_start:i])
                print(f"     File {file_start//19 + 1}: packets {file_start+1}-{i}, {download_size:,} bytes")
                file_start = i
            prev_time = data['timestamp']
        
        # Last file
        download_size = sum(d['size'] for d in download_data[file_start:])
        print(f"     File {file_start//19 + 1}: packets {file_start+1}-{len(download_data)}, {download_size:,} bytes")

if __name__ == "__main__":
    calculate_ftp_file_sizes()