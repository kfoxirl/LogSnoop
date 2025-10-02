"""
Command Line Interface for LogSnoop
"""

import argparse
import json
import sys
import os
from pathlib import Path
from logsnoop.core import LogParser


def format_bytes(bytes_value):
    """Format bytes into human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def format_bytes_with_raw(bytes_value):
    """Format bytes showing both raw bytes and human readable format."""
    if bytes_value < 1024:
        return f"{int(bytes_value)} bytes"
    
    # Calculate KB
    kb_value = bytes_value / 1024.0
    return f"{int(bytes_value)} bytes / {kb_value:.2f} KB"


def format_table_entry(entry, max_widths):
    """Format a log entry as a table row."""
    # Truncate fields if they exceed max width
    def truncate(text, max_width):
        if len(text) <= max_width:
            return text.ljust(max_width)
        return text[:max_width-3] + "..."
    
    line_num = str(entry.get('line_number', '')).ljust(max_widths['line_number'])
    timestamp = truncate(entry.get('timestamp', ''), max_widths['timestamp'])
    source_ip = truncate(entry.get('source_ip', ''), max_widths['source_ip'])
    dest_ip = truncate(entry.get('destination_ip', ''), max_widths['destination_ip'])
    bytes_val = truncate(str(entry.get('bytes_transferred', '')), max_widths['bytes'])
    event_type = truncate(entry.get('event_type', ''), max_widths['event_type'])
    status = truncate(entry.get('status', ''), max_widths['status'])
    
    return f"│ {line_num} │ {timestamp} │ {source_ip} │ {dest_ip} │ {bytes_val} │ {event_type} │ {status} │"


def calculate_column_widths(entries):
    """Calculate optimal column widths based on entry data."""
    max_widths = {
        'line_number': len('Line'),
        'timestamp': len('Timestamp'),
        'source_ip': len('Source IP'),
        'destination_ip': len('Destination IP'),
        'bytes': len('Bytes'),
        'event_type': len('Event Type'),
        'status': len('Status')
    }
    
    for entry in entries:
        max_widths['line_number'] = max(max_widths['line_number'], len(str(entry.get('line_number', ''))))
        max_widths['timestamp'] = max(max_widths['timestamp'], len(entry.get('timestamp', '')))
        max_widths['source_ip'] = max(max_widths['source_ip'], len(entry.get('source_ip', '')))
        max_widths['destination_ip'] = max(max_widths['destination_ip'], len(entry.get('destination_ip', '')))
        max_widths['bytes'] = max(max_widths['bytes'], len(str(entry.get('bytes_transferred', ''))))
        max_widths['event_type'] = max(max_widths['event_type'], len(entry.get('event_type', '')))
        max_widths['status'] = max(max_widths['status'], len(entry.get('status', '')))
    
    # Limit column widths to reasonable maximums
    max_widths['timestamp'] = min(max_widths['timestamp'], 25)
    max_widths['source_ip'] = min(max_widths['source_ip'], 20)
    max_widths['destination_ip'] = min(max_widths['destination_ip'], 20)
    max_widths['event_type'] = min(max_widths['event_type'], 20)  # Expanded to fit "network_transfer"
    max_widths['status'] = min(max_widths['status'], 12)
    
    return max_widths


def create_table_header(max_widths):
    """Create table header and separator."""
    line_header = "Line".ljust(max_widths['line_number'])
    timestamp_header = "Timestamp".ljust(max_widths['timestamp'])
    source_header = "Source IP".ljust(max_widths['source_ip'])
    dest_header = "Destination IP".ljust(max_widths['destination_ip'])
    bytes_header = "Bytes".ljust(max_widths['bytes'])
    event_header = "Event Type".ljust(max_widths['event_type'])
    status_header = "Status".ljust(max_widths['status'])
    
    header = f"┌─{'-' * max_widths['line_number']}─┬─{'-' * max_widths['timestamp']}─┬─{'-' * max_widths['source_ip']}─┬─{'-' * max_widths['destination_ip']}─┬─{'-' * max_widths['bytes']}─┬─{'-' * max_widths['event_type']}─┬─{'-' * max_widths['status']}─┐"
    title_row = f"│ {line_header} │ {timestamp_header} │ {source_header} │ {dest_header} │ {bytes_header} │ {event_header} │ {status_header} │"
    separator = f"├─{'-' * max_widths['line_number']}─┼─{'-' * max_widths['timestamp']}─┼─{'-' * max_widths['source_ip']}─┼─{'-' * max_widths['destination_ip']}─┼─{'-' * max_widths['bytes']}─┼─{'-' * max_widths['event_type']}─┼─{'-' * max_widths['status']}─┤"
    
    return header, title_row, separator


def create_table_footer(max_widths):
    """Create table footer."""
    return f"└─{'-' * max_widths['line_number']}─┴─{'-' * max_widths['timestamp']}─┴─{'-' * max_widths['source_ip']}─┴─{'-' * max_widths['destination_ip']}─┴─{'-' * max_widths['bytes']}─┴─{'-' * max_widths['event_type']}─┴─{'-' * max_widths['status']}─┘"


def paginate_table_view(entries, page_size=20, clear_screen=True):
    """Display log entries in a paginated table format similar to 'less'."""
    if not entries:
        print("No entries to display.")
        return
    
    max_widths = calculate_column_widths(entries)
    header, title_row, separator = create_table_header(max_widths)
    footer = create_table_footer(max_widths)
    
    total_entries = len(entries)
    current_page = 0
    
    while True:
        # Clear screen (works on both Windows and Unix) - optional
        if clear_screen:
            os.system('cls' if os.name == 'nt' else 'clear')
        
        start_idx = current_page * page_size
        end_idx = min(start_idx + page_size, total_entries)
        current_entries = entries[start_idx:end_idx]
        
        # Display table
        print(header)
        print(title_row)
        print(separator)
        
        for entry in current_entries:
            print(format_table_entry(entry, max_widths))
        
        print(footer)
        
        # Display navigation info
        page_info = f"Page {current_page + 1} of {(total_entries - 1) // page_size + 1} | "
        page_info += f"Showing entries {start_idx + 1}-{end_idx} of {total_entries}"
        print(f"\n{page_info}")
        print("Navigation: [n]ext page, [p]revious page, [q]uit, [g]oto page, [h]elp")
        
        # Get user input
        try:
            choice = input("\nEnter command: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting table view.")
            break
        
        if choice in ['q', 'quit', 'exit']:
            print("Exiting table view.")
            break
        elif choice in ['n', 'next']:
            if end_idx < total_entries:
                current_page += 1
            else:
                print("Already at last page.")
                input("Press Enter to continue...")
        elif choice in ['p', 'prev', 'previous']:
            if current_page > 0:
                current_page -= 1
            else:
                print("Already at first page.")
                input("Press Enter to continue...")
        elif choice.startswith('g'):
            try:
                # Handle both "g5" and "g 5" formats
                page_num_str = choice[1:].strip() or input("Enter page number: ")
                page_num = int(page_num_str) - 1
                max_page = (total_entries - 1) // page_size
                if 0 <= page_num <= max_page:
                    current_page = page_num
                else:
                    print(f"Page must be between 1 and {max_page + 1}")
                    input("Press Enter to continue...")
            except ValueError:
                print("Invalid page number.")
                input("Press Enter to continue...")
        elif choice in ['h', 'help']:
            print("\nTable View Help:")
            print("  n, next     - Go to next page")
            print("  p, prev     - Go to previous page") 
            print("  g[num]      - Go to specific page (e.g., 'g5' or 'g 5')")
            print("  q, quit     - Exit table view")
            print("  h, help     - Show this help")
            input("\nPress Enter to continue...")
        else:
            print("Unknown command. Type 'h' for help.")
            input("Press Enter to continue...")


def print_summary(summary):
    """Print summary statistics in a readable format."""
    print("\n" + "="*50)
    print("SUMMARY STATISTICS")
    print("="*50)
    
    for key, value in summary.items():
        if key.startswith('total_bytes'):
            print(f"{key.replace('_', ' ').title()}: {format_bytes(value)}")
        elif key == 'flag' and 'decoded_flag' in summary and summary['decoded_flag'] != value:
            # Show both raw and decoded flag if they're different
            print(f"{key.replace('_', ' ').title()}: {value}")
            print(f"Decoded Flag: {summary['decoded_flag']}")
        elif key == 'decoded_flag':
            # Skip decoded_flag as we handle it above
            continue
        elif key == 'creation_timestamp':
            # Special handling for creation timestamp to indicate UTC
            print(f"Creation Timestamp (UTC): {value}")
        elif isinstance(value, float):
            print(f"{key.replace('_', ' ').title()}: {value:.2f}")
        else:
            print(f"{key.replace('_', ' ').title()}: {value}")


def print_query_results(results, query_type):
    """Print query results in a readable format."""
    print(f"\n" + "="*50)
    print(f"QUERY RESULTS: {query_type.upper()}")
    print("="*50)
    
    # Special handling for top_data_senders
    if query_type == 'top_data_senders' and isinstance(results, dict):
        if 'top_sender' in results and results['top_sender']['ip']:
            print(f"Top Data Sender: {results['top_sender']['ip']}")
            print(f"Bytes Sent: {format_bytes_with_raw(results['top_sender']['bytes_sent'])}")
            print(f"Total IPs Analyzed: {results['total_ips']}")
            print("\nTop Data Senders:")
            for ip, bytes_sent in results['top_senders'].items():
                print(f"  {ip}: {format_bytes_with_raw(bytes_sent)}")
        else:
            print("No data senders found.")
        return
    
    # Special handling for busiest_day
    if query_type == 'busiest_day' and isinstance(results, dict):
        if results['busiest_day']:
            print(f"Busiest Day: {results['busiest_day']}")
            print(f"Total Bytes Transferred: {format_bytes_with_raw(results['total_bytes'])}")
            print(f"Total Connections: {results['total_connections']:,}")
            print(f"Analysis Period: {results['total_days']} days")
            
            print("\nDaily Breakdown (Top 10):")
            count = 0
            for day, stats in results['daily_breakdown'].items():
                if count >= 10:  # Limit to top 10 days
                    break
                print(f"  {day}: {format_bytes_with_raw(stats['bytes'])} ({stats['connections']:,} connections)")
                count += 1
        else:
            print("No traffic data found with valid timestamps.")
        return
    
    if isinstance(results, dict):
        if 'by_user' in results or 'by_ip' in results or 'by_path' in results:
            # Handle nested dictionary results
            for key, value in results.items():
                if isinstance(value, dict):
                    print(f"\n{key.replace('_', ' ').title()}:")
                    for sub_key, sub_value in list(value.items())[:20]:  # Limit to top 20
                        if isinstance(sub_value, int) and 'bytes' in key:
                            print(f"  {sub_key}: {format_bytes(sub_value)}")
                        else:
                            print(f"  {sub_key}: {sub_value}")
                else:
                    if isinstance(value, int) and 'bytes' in key:
                        print(f"{key.replace('_', ' ').title()}: {format_bytes(value)}")
                    else:
                        print(f"{key.replace('_', ' ').title()}: {value}")
        else:
            # Handle simple dictionary results
            for key, value in list(results.items())[:20]:  # Limit to top 20
                print(f"{key}: {value}")
    elif isinstance(results, list):
        if len(results) > 0 and isinstance(results[0], dict):
            # Handle list of dictionaries (log entries)
            print(f"Found {len(results)} entries:")
            for i, entry in enumerate(results[:10]):  # Show first 10 entries
                print(f"\nEntry {i+1}:")
                for key, value in entry.items():
                    if key not in ['raw_line', 'line_number']:  # Skip verbose fields
                        print(f"  {key}: {value}")
            if len(results) > 10:
                print(f"\n... and {len(results) - 10} more entries")
        else:
            # Handle simple list
            for item in results[:20]:  # Limit to top 20
                print(f"  {item}")
    else:
        print(results)


def main():
    parser = argparse.ArgumentParser(description='LogSnoop - Log Parser with Plugin Architecture')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List plugins command
    list_parser = subparsers.add_parser('list-plugins', help='List available plugins')
    list_parser.add_argument('--db', default='logsnoop.db', help='Database file path')
    
    # Parse command
    parse_parser = subparsers.add_parser('parse', help='Parse a log file')
    parse_parser.add_argument('file', help='Path to log file')
    parse_parser.add_argument('plugin', help='Plugin name to use')
    parse_parser.add_argument('--db', default='logsnoop.db', help='Database file path')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Query parsed logs')
    query_parser.add_argument('plugin', help='Plugin name')
    query_parser.add_argument('query_type', help='Query type')
    query_parser.add_argument('--db', default='logsnoop.db', help='Database file path')
    query_parser.add_argument('--limit', type=int, help='Limit results')
    query_parser.add_argument('--ip', help='Filter by IP address')
    query_parser.add_argument('--user', help='Filter by username')
    query_parser.add_argument('--status', help='Filter by status')
    query_parser.add_argument('--by-ip', action='store_true', help='Group by IP')
    query_parser.add_argument('--by-user', action='store_true', help='Group by user')
    query_parser.add_argument('--by-path', action='store_true', help='Group by path')
    query_parser.add_argument('--by-type', action='store_true', help='Group by type')
    query_parser.add_argument('--by-status', action='store_true', help='Group by status')
    query_parser.add_argument('--period', choices=['hour', 'day', 'month'], help='Time period for grouping')
    query_parser.add_argument('--by-bytes', action='store_true', help='Sort by bytes instead of count')
    query_parser.add_argument('--sort-by', choices=['connections', 'bytes'], help='Sort criteria for results')
    query_parser.add_argument('--file-id', type=int, help='Query specific file by ID (default: all files for plugin)')
    
    # List files command
    files_parser = subparsers.add_parser('list-files', help='List parsed files')
    files_parser.add_argument('--db', default='logsnoop.db', help='Database file path')
    
    # Summary command
    summary_parser = subparsers.add_parser('summary', help='Show summary for a file')
    summary_parser.add_argument('file_id', type=int, help='File ID')
    summary_parser.add_argument('--db', default='logsnoop.db', help='Database file path')
    
    # View command (table format with pagination)
    view_parser = subparsers.add_parser('view', help='View log entries in table format with pagination')
    view_parser.add_argument('plugin', help='Plugin name')
    view_parser.add_argument('--db', default='logsnoop.db', help='Database file path')
    view_parser.add_argument('--file-id', type=int, help='View specific file by ID (default: all files for plugin)')
    view_parser.add_argument('--page-size', type=int, default=20, help='Number of entries per page (default: 20)')
    view_parser.add_argument('--ip', help='Filter by IP address')
    view_parser.add_argument('--limit', type=int, help='Limit total number of entries shown')
    view_parser.add_argument('--no-clear', action='store_true', help='Don\'t clear screen between pages')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        log_parser = LogParser(args.db)
        
        if args.command == 'list-plugins':
            plugins = log_parser.get_available_plugins()
            print("Available plugins:")
            for plugin_name in plugins:
                plugin = log_parser.plugins[plugin_name]
                print(f"  {plugin_name}: {plugin.description}")
                print(f"    Supported queries: {', '.join(plugin.supported_queries)}")
                print()
        
        elif args.command == 'parse':
            if not Path(args.file).exists():
                print(f"Error: File '{args.file}' not found")
                sys.exit(1)
            
            if args.plugin not in log_parser.get_available_plugins():
                print(f"Error: Plugin '{args.plugin}' not found")
                print("Available plugins:", ', '.join(log_parser.get_available_plugins()))
                sys.exit(1)
            
            print(f"Parsing '{args.file}' with plugin '{args.plugin}'...")
            result = log_parser.parse_log_file(args.file, args.plugin)
            
            print(f"Successfully parsed {result['entries_count']} entries")
            print(f"File ID: {result['file_id']}")
            
            if result['summary']:
                print_summary(result['summary'])
        
        elif args.command == 'query':
            if args.plugin not in log_parser.get_available_plugins():
                print(f"Error: Plugin '{args.plugin}' not found")
                sys.exit(1)
            
            plugin = log_parser.plugins[args.plugin]
            if args.query_type not in plugin.supported_queries:
                print(f"Error: Query '{args.query_type}' not supported by plugin '{args.plugin}'")
                print(f"Supported queries: {', '.join(plugin.supported_queries)}")
                sys.exit(1)
            
            # Build query parameters
            kwargs = {}
            if args.limit:
                kwargs['limit'] = args.limit
            if args.ip:
                kwargs['ip_address'] = args.ip
            if args.user:
                kwargs['username'] = args.user
            if args.status:
                kwargs['status'] = args.status
            if args.by_ip:
                kwargs['by_ip'] = True
            if args.by_user:
                kwargs['by_user'] = True
            if args.by_path:
                kwargs['by_path'] = True
            if args.by_type:
                kwargs['by_type'] = True
            if args.by_status:
                kwargs['by_status'] = True
            if args.period:
                kwargs['period'] = args.period
            if args.by_bytes:
                kwargs['by_bytes'] = True
            if args.sort_by:
                kwargs['sort_by'] = args.sort_by
            if hasattr(args, 'file_id') and args.file_id:
                kwargs['file_id'] = args.file_id
            
            results = log_parser.query_logs(args.plugin, args.query_type, **kwargs)
            print_query_results(results, args.query_type)
        
        elif args.command == 'list-files':
            files = log_parser.list_parsed_files()
            if not files:
                print("No files have been parsed yet.")
            else:
                print("Parsed files:")
                for file_info in files:
                    print(f"  ID: {file_info['id']}")
                    print(f"    Path: {file_info['file_path']}")
                    print(f"    Plugin: {file_info['plugin_name']}")
                    print(f"    Parsed: {file_info['parsed_at']}")
                    print(f"    Size: {format_bytes(file_info['file_size'])}")
                    print(f"    Lines: {file_info['line_count']}")
                    print()
        
        elif args.command == 'summary':
            summary = log_parser.get_file_summary(args.file_id)
            if not summary:
                print(f"No summary found for file ID {args.file_id}")
            else:
                print_summary(summary)
        
        elif args.command == 'view':
            if args.plugin not in log_parser.get_available_plugins():
                print(f"Error: Plugin '{args.plugin}' not found")
                print("Available plugins:", ', '.join(log_parser.get_available_plugins()))
                sys.exit(1)
            
            # Get entries to display
            if args.file_id:
                entries = log_parser.db.get_entries_by_file(args.file_id)
                # Verify the file uses the specified plugin
                files = log_parser.list_parsed_files()
                file_info = next((f for f in files if f['id'] == args.file_id), None)
                if not file_info:
                    print(f"Error: File ID {args.file_id} not found")
                    sys.exit(1)
                if file_info['plugin_name'] != args.plugin:
                    print(f"Error: File ID {args.file_id} was parsed with plugin '{file_info['plugin_name']}', not '{args.plugin}'")
                    sys.exit(1)
                print(f"Viewing entries from file: {file_info['file_path']}")
            else:
                entries = log_parser.db.get_entries_by_plugin(args.plugin)
                print(f"Viewing all entries parsed with plugin: {args.plugin}")
            
            if not entries:
                print("No entries found.")
                sys.exit(0)
            
            # Apply filters
            if args.ip:
                entries = [e for e in entries if 
                          args.ip in e.get('source_ip', '') or args.ip in e.get('destination_ip', '')]
                print(f"Filtered by IP containing '{args.ip}': {len(entries)} entries")
            
            if args.limit:
                entries = entries[:args.limit]
                print(f"Limited to first {args.limit} entries")
            
            # Sort by line number for consistent display
            entries.sort(key=lambda x: (x.get('file_id', 0), x.get('line_number', 0)))
            
            print(f"\nTotal entries to display: {len(entries)}")
            print("Starting table view...\n")
            
            # Start paginated table view
            paginate_table_view(entries, args.page_size, clear_screen=not args.no_clear)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()