# SKY Binary Log Plugin Documentation

## Overview

The SKY plugin enables LogSnoop to parse custom SKY binary log files that contain network traffic data. This plugin handles the binary format parsing, header extraction, and provides comprehensive querying capabilities for network analysis.

## SKY File Format Support

The plugin supports SKYv1 binary format with the following specifications:

### Header Structure
- **Magic Bytes**: `0x91534B590D0A1A0A` (8 bytes)
- **Version**: `0x01` for SKYv1 (1 byte) 
- **Creation Timestamp**: Unix timestamp (4 bytes, big-endian)
- **Hostname Length**: Length of hostname string (4 bytes, big-endian)
- **Hostname**: Variable length UTF-8 string
- **Flag Length**: Length of flag string (4 bytes, big-endian)
- **Flag**: Variable length string (can be encrypted/encoded)
- **Number of Entries**: Count of traffic records (4 bytes, big-endian)

### Body Structure
Each traffic entry contains (16 bytes total):
- **Source IP**: IPv4 address as integer (4 bytes, big-endian)
- **Destination IP**: IPv4 address as integer (4 bytes, big-endian)
- **Timestamp**: Unix timestamp when transfer started (4 bytes, big-endian)
- **Bytes Transferred**: Amount of data transferred (4 bytes, big-endian)

## Usage Examples

### Parsing a SKY File
```bash
# Parse binary SKY log file
logsnoop parse network_traffic.sky sky_log

# View parsed file summary
logsnoop summary <file_id>
```

### Network Traffic Analysis
```bash
# Get overall traffic summary
logsnoop query sky_log traffic_summary

# Find top bandwidth consumers
logsnoop query sky_log top_talkers --by-bytes --limit 10

# Find most active IPs by connection count
logsnoop query sky_log top_talkers --limit 10

# Analyze traffic between specific IP pairs
logsnoop query sky_log ip_pairs --limit 10 --sort-by bytes
```

### Source/Destination Analysis
```bash
# Get bytes sent by each source IP
logsnoop query sky_log bytes_by_source

# Get bytes received by each destination IP  
logsnoop query sky_log bytes_by_destination

# Get connection counts by source
logsnoop query sky_log connections_by_source

# Get connection counts by destination
logsnoop query sky_log connections_by_destination
```

### Temporal Analysis
```bash
# View traffic over time (hourly)
logsnoop query sky_log traffic_timeline --period hour

# View bandwidth usage over time (daily)
logsnoop query sky_log bandwidth_usage --period day
```

### IP-Specific Queries
```bash
# Get all traffic involving a specific IP
logsnoop query sky_log traffic_by_ip --ip 192.168.1.100

# View traffic patterns for an IP
logsnoop query sky_log traffic_by_ip --ip 10.0.0.5
```

## Supported Query Types

| Query Type | Description | Options |
|------------|-------------|---------|
| `traffic_summary` | Overall traffic statistics | None |
| `top_talkers` | Most active IPs | `--by-bytes`, `--limit` |
| `bytes_by_source` | Data sent by source IPs | None |
| `bytes_by_destination` | Data received by destination IPs | None |
| `connections_by_source` | Connection counts by source | None |
| `connections_by_destination` | Connection counts by destination | None |
| `traffic_timeline` | Traffic over time | `--period` (hour/day/month) |
| `bandwidth_usage` | Bandwidth over time | `--period` (hour/day/month) |
| `ip_pairs` | Source-destination pairs | `--limit`, `--sort-by` (connections/bytes) |
| `traffic_by_ip` | Traffic for specific IP | `--ip <address>` |

## Python API Usage

```python
from logsnoop.core import LogParser

# Initialize parser
parser = LogParser("network_logs.db")

# Parse SKY binary file
result = parser.parse_log_file("traffic.sky", "sky_log")
print(f"Parsed {result['entries_count']} network transfers")

# Get traffic summary
summary = parser.query_logs("sky_log", "traffic_summary")
print(f"Total bandwidth: {summary['total_bytes']} bytes")

# Find top bandwidth consumers
top_talkers = parser.query_logs("sky_log", "top_talkers", by_bytes=True, limit=5)
for ip, bytes_transferred in top_talkers.items():
    print(f"{ip}: {bytes_transferred:,} bytes")

# Analyze IP communication patterns
ip_pairs = parser.query_logs("sky_log", "ip_pairs", limit=10, sort_by="bytes")
for pair, stats in ip_pairs.items():
    print(f"{pair}: {stats['connections']} connections, {stats['bytes']} bytes")
```

## Binary File Creation

Use the included sample generator to create test SKY files:

```python
# Create sample SKY file
python create_sample_sky.py

# This creates a sample.sky file with:
# - Header with hostname and flag
# - 8 sample network transfers
# - Various IP addresses and byte counts
```

## Network Security Analysis

The SKY plugin is particularly useful for:

1. **Bandwidth Monitoring**: Track data usage by IP and time period
2. **Traffic Pattern Analysis**: Identify unusual communication patterns
3. **Network Mapping**: Discover active hosts and communication flows
4. **Anomaly Detection**: Find outliers in traffic volume or frequency
5. **Compliance Reporting**: Generate network usage reports

## Error Handling

The plugin handles various error conditions:
- Invalid magic bytes
- Unsupported versions  
- Corrupted header data
- Incomplete entries
- Invalid IP addresses

Parse errors are reported in the summary with detailed error messages.

## Performance Considerations

- Binary parsing is efficient for large files
- Memory usage scales with file size
- Supports files with millions of entries
- Query performance depends on result set size
- Use `--limit` for large datasets to improve performance