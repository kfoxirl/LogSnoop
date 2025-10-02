# LogSnoop - Python Log Parser with Plugin Architecture

LogSnoop is a flexible log parser that can analyze different types of logs through a plugin-based architecture. It supports SSH authentication logs, FTP server logs, HTTP access logs, and simple login logs, storing results in a flat file database for easy querying.

## Features

- **Plugin Architecture**: Easily extensible with custom log parsers
- **Multiple Log Types**: Built-in support for SSH, FTP, HTTP, and login logs
- **Flat File Database**: Simple JSON-based storage with no external dependencies
- **Rich Querying**: Comprehensive query system for each log type
- **Interactive Table View**: Paginated table display with `less`-like navigation
- **CLI Interface**: Command-line tool for parsing and querying logs
- **Statistics**: Automatic generation of summary statistics
- **Filtering & Search**: Filter log entries by IP addresses and other criteria

## Supported Log Types

### 1. SSH Authentication Logs (`ssh_auth`)
- Parses SSH authentication logs (auth.log, secure)
- Tracks failed/successful logins, connections, disconnections
- Identifies suspicious login patterns
- **Queries**: `failed_logins`, `successful_logins`, `connection_count`, `suspicious_logins`, `top_attackers`, `login_attempts_by_user`, `connections_by_ip`

### 2. FTP Server Logs (`ftp_log`)  
- Parses FTP server logs (vsftpd, proftpd)
- Tracks uploads, downloads, file operations, bytes transferred
- Monitors login attempts and user activity
- **Queries**: `uploads`, `downloads`, `login_attempts`, `failed_logins`, `successful_logins`, `bytes_transferred`, `top_uploaders`, `top_downloaders`, `file_operations`, `connections_by_ip`

### 3. HTTP Access Logs (`http_access`)
- Parses HTTP web server access logs (Apache, Nginx)
- Tracks requests, status codes, bandwidth usage, response times
- Analyzes traffic patterns and errors
- **Queries**: `requests_by_status`, `requests_by_ip`, `requests_by_path`, `error_requests`, `bytes_served`, `top_pages`, `top_referrers`, `top_user_agents`, `bandwidth_usage`, `response_time_stats`

### 4. Simple Login Logs (`simple_login`)
- Parses simple login logs with timestamp, IP, username format
- Tracks user login patterns and frequency
- **Queries**: `logins_by_user`, `logins_by_ip`, `login_count`, `unique_users`, `unique_ips`, `login_timeline`, `frequent_users`, `frequent_ips`

### 5. SKY Binary Logs (`sky_log`)
- Parses SKY binary network traffic logs (custom binary format)
- Tracks network connections, data transfers, bandwidth usage
- Supports header metadata (hostname, flags, creation timestamp)
- **Queries**: `traffic_by_ip`, `top_talkers`, `traffic_summary`, `bytes_by_source`, `bytes_by_destination`, `connections_by_source`, `connections_by_destination`, `traffic_timeline`, `ip_pairs`, `bandwidth_usage`

## Installation

### Quick Installation (Linux/macOS)
```bash
# Clone the repository
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop

# Install for current user (recommended)
make install-user

# OR install system-wide (requires sudo)
sudo make install-system
```

### Windows Installation
```batch
# Clone the repository
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop

# Run the Windows installer
install.bat
```

### Manual Installation
```bash
# Clone and setup virtual environment
git clone https://github.com/kfoxirl/LogSnoop.git
cd LogSnoop
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Use directly
python cli.py --help
```

### Installation Options
- **User Installation**: `make install-user` - Installs to `~/.local/` (no sudo required)
- **System Installation**: `sudo make install-system` - Installs to `/usr/local/` (available for all users)
- **Custom Location**: `make install PREFIX=/opt/logsnoop` - Install to custom directory
- **Windows**: `install.bat` - Automated Windows installation with PATH setup

### Post-Installation
After installation, LogSnoop is available as a system command:
```bash
# View manual page
man logsnoop

# Run LogSnoop
logsnoop --help
logsnoop list-plugins
```

## Usage

### Command Line Interface

#### List Available Plugins
```bash
logsnoop list-plugins
```

#### Parse a Log File
```bash
# Parse SSH authentication log
logsnoop parse /var/log/auth.log ssh_auth

# Parse FTP log with custom database
logsnoop parse /var/log/vsftpd.log ftp_log --db custom.db

# Parse HTTP access log
logsnoop parse /var/log/apache2/access.log http_access

# Parse SKY binary log
logsnoop parse network_traffic.sky sky_log
```

#### Query Parsed Logs
```bash
# Get failed SSH login attempts
logsnoop query ssh_auth failed_logins

# Get top attackers (limit to 5)
logsnoop query ssh_auth top_attackers --limit 5

# Get failed logins grouped by IP
logsnoop query ssh_auth failed_logins --by-ip

# Get bytes transferred by user in FTP logs
logsnoop query ftp_log bytes_transferred --by-user

# Get HTTP requests by status code
logsnoop query http_access requests_by_status

# Get login timeline by day
logsnoop query simple_login login_timeline --period day

# Get network traffic summary
logsnoop query sky_log traffic_summary

# Get top talkers by bytes transferred
logsnoop query sky_log top_talkers --limit 10 --by-bytes

# Get most active IP pairs
logsnoop query sky_log ip_pairs --limit 10 --sort-by bytes
```

#### List Parsed Files
```bash
logsnoop list-files
```

#### Show File Summary
```bash
logsnoop summary 1  # Show summary for file ID 1
```

#### View Log Entries in Table Format
```bash
# View all entries for a plugin in paginated table format
logsnoop view sky_log

# View specific file entries
logsnoop view sky_log --file-id 1

# Customize page size (default: 20)
logsnoop view sky_log --page-size 10

# Filter by IP address
logsnoop view sky_log --ip 192.168

# Limit total entries shown
logsnoop view sky_log --limit 100

# Disable screen clearing for terminal compatibility
logsnoop view sky_log --no-clear

# Combine options
logsnoop view sky_log --file-id 1 --ip 77.255 --page-size 5
```

**Table View Navigation:**
- `n` or `next` - Go to next page
- `p` or `prev` - Go to previous page
- `g[num]` - Go to specific page (e.g., `g5` or `g 5`)
- `q` or `quit` - Exit table view
- `h` or `help` - Show navigation help

**Table View Features:**
- **Paginated Display**: Browse through large datasets page by page
- **Filtering**: Filter entries by IP address patterns
- **Sorting**: Entries sorted by file ID and line number for consistency
- **Responsive Layout**: Automatically adjusts column widths based on data
- **Interactive Navigation**: `less`-like navigation with keyboard commands
- **Clean Output**: Well-formatted table with proper borders and alignment

### Python API

```python
from logsnoop.core import LogParser

# Initialize parser
parser = LogParser("my_logs.db")

# List available plugins
plugins = parser.get_available_plugins()
print(plugins)  # ['ssh_auth', 'ftp_log', 'http_access', 'simple_login', 'sky_log']

# Parse a log file
result = parser.parse_log_file("/var/log/auth.log", "ssh_auth")
print(f"Parsed {result['entries_count']} entries")

# Query the parsed data
failed_logins = parser.query_logs("ssh_auth", "failed_logins", by_ip=True)
print(failed_logins)

# Get summary statistics
summary = parser.get_file_summary(result['file_id'])
print(summary)
```

## Creating Custom Plugins

To create a custom plugin, inherit from `BaseLogPlugin`:

```python
from logsnoop.plugins.base import BaseLogPlugin
from typing import Dict, List, Any

class MyCustomPlugin(BaseLogPlugin):
    @property
    def name(self) -> str:
        return "my_custom"
    
    @property
    def description(self) -> str:
        return "My custom log parser"
    
    @property
    def supported_queries(self) -> List[str]:
        return ["my_query", "another_query"]
    
    def parse(self, log_content: str) -> Dict[str, Any]:
        # Parse log content and return structured data
        entries = []  # List of parsed log entries
        summary = {}  # Summary statistics
        
        # Your parsing logic here
        
        return {
            'entries': entries,
            'summary': summary
        }
    
    def query(self, query_type: str, log_entries: List[Dict[str, Any]], **kwargs) -> Any:
        # Implement your custom queries
        if query_type == "my_query":
            # Your query logic here
            return results
        else:
            raise ValueError(f"Unsupported query type: {query_type}")
```

Save the plugin as `logsnoop/plugins/my_custom.py` and it will be automatically loaded.

## Database Structure

LogSnoop uses a simple JSON-based flat file database with three main collections:

- **files**: Metadata about parsed log files
- **entries**: Individual parsed log entries
- **summaries**: Summary statistics for each file

## Sample Data Analysis

The project includes sample log files that demonstrate various attack patterns:

### SSH Brute Force Analysis
```bash
# Parse SSH auth log
logsnoop parse auth.log ssh_auth

# Find top attackers
logsnoop query ssh_auth top_attackers --limit 10

# Analyze failed login patterns
logsnoop query ssh_auth failed_logins --by-ip
```

### FTP Activity Monitoring
```bash
# Parse FTP log
logsnoop parse vsftpd.log ftp_log

# Check bandwidth usage
logsnoop query ftp_log bytes_transferred --by-user

# Monitor file operations
logsnoop query ftp_log file_operations --by-type
```

### Web Traffic Analysis
```bash
# Parse access log
logsnoop parse access.log http_access

# Check error rates
logsnoop query http_access error_requests --by-status

# Analyze bandwidth usage
logsnoop query http_access bandwidth_usage --period day

### Network Traffic Analysis
```bash
# Parse SKY binary log
logsnoop parse network_traffic.sky sky_log

# Get traffic summary
logsnoop query sky_log traffic_summary

# Find top bandwidth consumers
logsnoop query sky_log top_talkers --by-bytes --limit 10
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your plugin or enhancement
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Architecture

```
LogSnoop/
├── logsnoop/
│   ├── __init__.py          # Package initialization
│   ├── core.py              # Main parser engine
│   ├── database.py          # Flat file database
│   └── plugins/
│       ├── __init__.py
│       ├── base.py          # Base plugin class
│       ├── ssh_auth.py      # SSH authentication plugin
│       ├── ftp_log.py       # FTP server log plugin
│       ├── http_access.py   # HTTP access log plugin
│       ├── simple_login.py  # Simple login log plugin
│       └── sky_log.py       # SKY binary log plugin
├── cli.py                   # Command line interface
├── main.py                  # Entry point
├── setup.py                 # Package setup
└── README.md               # This file
```
