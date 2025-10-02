"""
LogSnoop Interactive Mode - User-friendly guided interface
"""

import os
import sys
import glob
from pathlib import Path
from logsnoop.core import LogParser

# Import readline for tab completion (Unix/Linux/Mac)
try:
    import readline
    HAS_READLINE = True
except ImportError:
    # Windows fallback - try pyreadline
    try:
        import pyreadline3 as readline
        HAS_READLINE = True
    except ImportError:
        # No readline available
        HAS_READLINE = False
        readline = None


class LogSnoopInteractive:
    """Interactive mode for LogSnoop with guided workflows."""
    
    def __init__(self, db_path='logsnoop.db'):
        self.log_parser = LogParser(db_path)
        self.db_path = db_path
        self._setup_tab_completion()
        
    def _setup_tab_completion(self):
        """Setup tab completion for file paths."""
        if HAS_READLINE and readline:
            try:
                # Set up tab completion
                readline.set_completer_delims(' \t\n`!@#$%^&*()=+[{]}\\|;:\'",<>?')
                readline.parse_and_bind("tab: complete")
            except AttributeError:
                # Readline module doesn't support these functions
                pass
            
    def _path_completer(self, text, state):
        """Custom completer for file paths."""
        # Expand user directory (~)
        if text.startswith('~'):
            text = os.path.expanduser(text)
            
        # Handle relative paths
        if not text.startswith('/') and not (len(text) > 1 and text[1] == ':'):
            # Convert to absolute path for completion
            text = os.path.join(os.getcwd(), text)
            
        # Get directory and filename parts
        dirname, basename = os.path.split(text)
        
        if not dirname:
            dirname = '.'
            
        try:
            # Get matching files and directories
            if basename:
                matches = glob.glob(os.path.join(dirname, basename + '*'))
            else:
                matches = glob.glob(os.path.join(dirname, '*'))
                
            # Filter to show directories and common log files
            filtered_matches = []
            for match in matches:
                if os.path.isdir(match):
                    # Add trailing slash for directories
                    filtered_matches.append(match + os.sep)
                else:
                    # Show files with common log extensions or any file
                    ext = os.path.splitext(match)[1].lower()
                    if ext in ['.log', '.txt', '.out', '.err', ''] or not ext:
                        filtered_matches.append(match)
                        
            # Return the match at the requested state
            if state < len(filtered_matches):
                return filtered_matches[state]
            else:
                return None
                
        except (OSError, IndexError):
            return None
    
    def _input_with_completion(self, prompt, enable_completion=True):
        """Input function with optional tab completion."""
        if HAS_READLINE and readline and enable_completion:
            try:
                # Set our custom completer
                old_completer = readline.get_completer()
                readline.set_completer(self._path_completer)
                
                try:
                    result = input(prompt)
                    return result
                finally:
                    # Restore old completer
                    readline.set_completer(old_completer)
            except AttributeError:
                # Readline functions not available, fall back to regular input
                return input(prompt)
        else:
            return input(prompt)
        
    def clear_screen(self):
        """Clear terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_header(self):
        """Print LogSnoop header with color."""
        print("\033[94m╔══════════════════════════════════════════╗\033[0m")
        print("\033[94m║\033[0m           \033[1mLogSnoop Interactive\033[0m           \033[94m║\033[0m") 
        print("\033[94m║\033[0m      \033[92mLog Analysis Made Simple\033[0m            \033[94m║\033[0m")
        print("\033[94m╚══════════════════════════════════════════╝\033[0m")
        print()
        
    def print_menu(self):
        """Print main menu with colors."""
        print("┌─────────────────────────────────────────┐")
        print("│ \033[1mWhat would you like to do?\033[0m              │")
        print("├─────────────────────────────────────────┤")
        print("│ \033[92m1.\033[0m Parse a new log file                 │")
        print("│ \033[92m2.\033[0m Query existing data                  │") 
        print("│ \033[92m3.\033[0m View parsed files                    │")
        print("│ \033[92m4.\033[0m Browse log entries (table view)     │")
        print("│ \033[92m5.\033[0m Show plugin information              │")
        print("│ \033[91m6.\033[0m Exit                                 │")
        print("└─────────────────────────────────────────┘")
        print()
        
    def get_user_choice(self, prompt, valid_choices):
        """Get validated user input."""
        while True:
            try:
                choice = input(f"\033[93m{prompt}\033[0m").strip()
                if choice in valid_choices:
                    return choice
                print(f"\033[91mInvalid choice. Please select from: {', '.join(valid_choices)}\033[0m")
            except (KeyboardInterrupt, EOFError):
                print("\n\033[92mGoodbye! 👋\033[0m")
                sys.exit(0)
                
    def select_plugin(self, purpose="use"):
        """Interactive plugin selection with descriptions."""
        plugins = self.log_parser.get_available_plugins()
        
        print(f"\n\033[94m🔌 Available Plugins\033[0m ({purpose}):")
        print("\033[90m" + "─" * 50 + "\033[0m")
        
        for i, plugin_name in enumerate(plugins, 1):
            plugin = self.log_parser.plugins[plugin_name]
            print(f"\033[92m{i}.\033[0m \033[1m{plugin_name}\033[0m")
            print(f"   \033[90m📝 {plugin.description}\033[0m")
            
            # Show some supported queries as examples
            queries = list(plugin.supported_queries)[:3]  # First 3 queries
            query_text = ", ".join(queries)
            if len(plugin.supported_queries) > 3:
                query_text += f", ... (+{len(plugin.supported_queries) - 3} more)"
            print(f"   \033[90m🔍 Example queries: {query_text}\033[0m")
            print()
            
        choice = self.get_user_choice(
            f"Select plugin (1-{len(plugins)}) or 'b' for back: ",
            [str(i) for i in range(1, len(plugins) + 1)] + ['b']
        )
        
        if choice == 'b':
            return None
            
        return list(plugins)[int(choice) - 1]
        
    def select_file_path(self):
        """Interactive file selection with validation and suggestions."""
        print("\n\033[94m📁 File Selection\033[0m")
        print("\033[90m" + "─" * 30 + "\033[0m")
        
        # Show some helpful examples and tab completion info
        print("\033[90mExamples:\033[0m")
        print("  \033[90m• C:\\logs\\access.log\033[0m")  
        print("  \033[90m• /var/log/auth.log\033[0m")
        print("  \033[90m• ./sample_logs/tomcat.log\033[0m")
        
        if HAS_READLINE:
            print("\n\033[92m💡 Tip: Use TAB for path completion!\033[0m")
        
        print()
        
        while True:
            file_path = self._input_with_completion("\033[93mEnter log file path (or 'b' for back): \033[0m").strip()
            
            if file_path == 'b':
                return None
                
            if not file_path:
                print("\033[91mPlease enter a file path.\033[0m")
                continue
                
            path = Path(file_path)
            if not path.exists():
                print(f"\033[91m❌ File not found: {file_path}\033[0m")
                
                # Offer to show current directory contents
                suggest = self.get_user_choice(
                    "Would you like to see files in current directory? (y/n): ", 
                    ['y', 'n']
                )
                if suggest == 'y':
                    try:
                        current_dir = Path('.')
                        log_files = [f for f in current_dir.iterdir() 
                                   if f.is_file() and f.suffix in ['.log', '.txt']]
                        if log_files:
                            print("\n\033[90mLog files in current directory:\033[0m")
                            for f in log_files[:10]:  # Show max 10 files
                                print(f"  \033[90m• {f}\033[0m")
                        else:
                            print("\033[90mNo .log or .txt files found in current directory.\033[0m")
                    except Exception:
                        print("\033[91mCouldn't list directory contents.\033[0m")
                continue
                
            if not path.is_file():
                print(f"\033[91m❌ Path is not a file: {file_path}\033[0m")
                continue
                
            return str(path.absolute())
            
    def parse_file_workflow(self):
        """Guided file parsing workflow with progress feedback."""
        self.clear_screen()
        self.print_header()
        print("\033[94m🔍 Parse New Log File\033[0m")
        print("\033[90m" + "=" * 40 + "\033[0m")
        
        # Select plugin
        plugin_name = self.select_plugin("parse files")
        if not plugin_name:
            return
            
        # Select file
        file_path = self.select_file_path()
        if not file_path:
            return
            
        # Show configuration summary
        print(f"\n\033[94m📋 Parsing Configuration:\033[0m")
        print(f"   \033[90m📄 File:\033[0m {file_path}")
        print(f"   \033[90m🔌 Plugin:\033[0m {plugin_name}")
        
        # Show file size for user awareness
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # > 1MB
                print(f"   \033[90m📊 Size:\033[0m {file_size / (1024*1024):.1f} MB")
            else:
                print(f"   \033[90m📊 Size:\033[0m {file_size} bytes")
        except:
            pass
        
        confirm = self.get_user_choice(
            "\nProceed with parsing? (y/n): ", ['y', 'n']
        )
        
        if confirm == 'y':
            try:
                print("\n\033[93m⏳ Parsing file...\033[0m")
                result = self.log_parser.parse_log_file(file_path, plugin_name)
                
                if result.get('duplicate'):
                    print(f"\n\033[93m⚠️  File was already parsed (duplicate detected)\033[0m")
                    print(f"\033[92m📊 File ID: {result['file_id']}\033[0m")
                else:
                    print(f"\n\033[92m✅ Successfully parsed {result['entries_count']:,} entries!\033[0m")
                    print(f"\033[92m📊 File ID: {result['file_id']}\033[0m")
                
                # Offer to show summary
                show_summary = self.get_user_choice(
                    "\nWould you like to see a summary? (y/n): ", ['y', 'n']
                )
                
                if show_summary == 'y':
                    summary = self.log_parser.get_file_summary(result['file_id'])
                    if summary:
                        self.display_summary(summary)
                    
                # Offer to run a query
                run_query = self.get_user_choice(
                    "\nWould you like to run a query on this data? (y/n): ", ['y', 'n']
                )
                
                if run_query == 'y':
                    self.query_workflow(plugin_name, result['file_id'])
                    return  # Skip the "Press Enter" since query workflow handles it
                    
            except Exception as e:
                print(f"\n\033[91m❌ Error parsing file: {e}\033[0m")
                
        input("\n\033[90mPress Enter to continue...\033[0m")
        
    def query_workflow(self, preselected_plugin=None, preselected_file_id=None):
        """Guided query workflow with result formatting."""
        if not preselected_plugin:
            self.clear_screen()
            self.print_header()
            print("\033[94m🔎 Query Log Data\033[0m")
            print("\033[90m" + "=" * 40 + "\033[0m")
        
        # Check if we have any parsed files
        files = self.log_parser.list_parsed_files()
        if not files:
            print("\033[91m❌ No parsed files found. Please parse a log file first.\033[0m")
            input("\n\033[90mPress Enter to continue...\033[0m")
            return
            
        # Select plugin if not preselected
        if preselected_plugin:
            plugin_name = preselected_plugin
        else:
            plugin_name = self.select_plugin("query")
            if not plugin_name:
                return
            
        # Load plugin and show queries
        plugin = self.log_parser.plugins[plugin_name]
        queries = list(plugin.supported_queries)
        
        print(f"\n\033[94m📊 Available Queries\033[0m for \033[1m{plugin_name}\033[0m:")
        print("\033[90m" + "─" * 50 + "\033[0m")
        
        # Group queries by category for better display
        for i, query in enumerate(queries, 1):
            category_color = self._get_query_color(query)
            print(f"{category_color}{i:2}.\033[0m {query}")
            
        choice = self.get_user_choice(
            f"\nSelect query (1-{len(queries)}) or 'b' for back: ",
            [str(i) for i in range(1, len(queries) + 1)] + ['b']
        )
        
        if choice == 'b':
            return
            
        query_type = queries[int(choice) - 1]
        
        # Execute query
        try:
            print(f"\n\033[93m⏳ Executing query: {query_type}\033[0m")
            
            kwargs = {}
            if preselected_file_id:
                kwargs['file_id'] = preselected_file_id
                
            results = self.log_parser.query_logs(plugin_name, query_type, **kwargs)
            
            print(f"\n\033[92m✅ Query completed!\033[0m")
            print("\033[90m" + "=" * 50 + "\033[0m")
            
            # Display results with better formatting
            self._display_query_results(results, query_type)
                
        except Exception as e:
            print(f"\n\033[91m❌ Error executing query: {e}\033[0m")
            
        input("\n\033[90mPress Enter to continue...\033[0m")
        
    def _get_query_color(self, query_type):
        """Get color for query type based on category."""
        if 'error' in query_type or 'failed' in query_type:
            return "\033[91m"  # Red for errors
        elif 'top' in query_type or 'bandwidth' in query_type:
            return "\033[92m"  # Green for top/stats
        elif 'by_' in query_type or 'analysis' in query_type:
            return "\033[93m"  # Yellow for grouping
        else:
            return "\033[94m"  # Blue for general
            
    def _display_query_results(self, results, query_type):
        """Display query results with nice formatting."""
        if isinstance(results, dict):
            for key, value in results.items():
                if isinstance(value, (int, float)):
                    if key.endswith('bytes') or 'size' in key.lower():
                        # Format bytes nicely
                        print(f"\033[1m{key}:\033[0m {self._format_bytes(value)}")
                    else:
                        print(f"\033[1m{key}:\033[0m {value:,}")
                elif isinstance(value, dict) and len(value) <= 20:
                    print(f"\033[1m{key}:\033[0m")
                    for sub_key, sub_val in list(value.items())[:10]:  # Show max 10
                        print(f"  • {sub_key}: {sub_val}")
                    if len(value) > 10:
                        print(f"  \033[90m... and {len(value) - 10} more\033[0m")
                else:
                    print(f"\033[1m{key}:\033[0m {value}")
        elif isinstance(results, list):
            print(f"Found {len(results)} results:")
            for i, item in enumerate(results[:15], 1):  # Show first 15
                print(f"  \033[92m{i}.\033[0m {item}")
            if len(results) > 15:
                print(f"  \033[90m... and {len(results) - 15} more results\033[0m")
        else:
            print(results)
            
    def _format_bytes(self, bytes_value):
        """Format bytes into human readable format."""
        if bytes_value < 1024:
            return f"{bytes_value} bytes"
        elif bytes_value < 1024 ** 2:
            return f"{bytes_value / 1024:.1f} KB"
        elif bytes_value < 1024 ** 3:
            return f"{bytes_value / (1024 ** 2):.1f} MB"
        else:
            return f"{bytes_value / (1024 ** 3):.1f} GB"
        
    def list_files_workflow(self):
        """Show parsed files with enhanced information."""
        self.clear_screen()
        self.print_header()
        print("\033[94m📁 Parsed Files\033[0m")
        print("\033[90m" + "=" * 40 + "\033[0m")
        
        files = self.log_parser.list_parsed_files()
        
        if not files:
            print("\033[93mNo parsed files found.\033[0m")
            print("Use option 1 to parse your first log file!")
        else:
            for i, file_info in enumerate(files, 1):
                print(f"\033[92m{i}. ID: {file_info['id']}\033[0m")
                print(f"   \033[90m📄 File:\033[0m {file_info['file_path']}")
                print(f"   \033[90m🔌 Plugin:\033[0m {file_info['plugin_name']}")
                print(f"   \033[90m📊 Entries:\033[0m {file_info['entry_count']:,}")
                print(f"   \033[90m📅 Parsed:\033[0m {file_info['created_at']}")
                if i < len(files):  # Don't print separator after last item
                    print("\033[90m" + "─" * 50 + "\033[0m")
                
        input("\n\033[90mPress Enter to continue...\033[0m")
        
    def show_plugin_info_workflow(self):
        """Display detailed plugin information."""
        self.clear_screen()
        self.print_header()
        print("\033[94m🔌 Plugin Information\033[0m")
        print("\033[90m" + "=" * 40 + "\033[0m")
        
        plugins = self.log_parser.get_available_plugins()
        
        for plugin_name in plugins:
            plugin = self.log_parser.plugins[plugin_name]
            print(f"\n\033[1m🔧 {plugin_name}\033[0m")
            print(f"\033[90m📝 Description:\033[0m {plugin.description}")
            
            queries = list(plugin.supported_queries)
            print(f"\033[90m🔍 Supported Queries ({len(queries)}):\033[0m")
            
            # Group queries for better readability
            for i, query in enumerate(queries):
                color = self._get_query_color(query)
                print(f"   {color}• {query}\033[0m")
                
            print("\033[90m" + "─" * 50 + "\033[0m")
                
        input("\n\033[90mPress Enter to continue...\033[0m")
        
    def table_view_workflow(self):
        """Launch table view mode."""
        self.clear_screen()
        self.print_header()
        print("\033[94m📋 Browse Log Entries\033[0m")
        print("\033[90m" + "=" * 40 + "\033[0m")
        
        # Check if we have any parsed files
        files = self.log_parser.list_parsed_files()
        if not files:
            print("\033[91m❌ No parsed files found. Please parse a log file first.\033[0m")
            input("\n\033[90mPress Enter to continue...\033[0m")
            return
            
        # Select plugin
        plugin_name = self.select_plugin("view entries")
        if not plugin_name:
            return
            
        print(f"\n\033[93m🚀 Launching table view for {plugin_name}...\033[0m")
        print("\033[90mNote: Use 'q' in table view to return to interactive mode.\033[0m")
        input("\n\033[90mPress Enter to continue...\033[0m")
        
        # This would integrate with the existing table view
        # For now, we'll show a placeholder
        print("\n\033[94m📋 Table View Integration\033[0m")
        print("This would launch the existing paginated table view...")
        print("Command equivalent: logsnoop view " + plugin_name)
        
        input("\n\033[90mPress Enter to continue...\033[0m")
        
    def display_summary(self, summary):
        """Display file summary in a nice format."""
        print(f"\n\033[94m📊 File Summary\033[0m")
        print("\033[90m" + "─" * 30 + "\033[0m")
        for key, value in summary.items():
            if key not in ['id', 'file_id']:  # Skip internal IDs
                formatted_key = key.replace('_', ' ').title()
                if isinstance(value, (int, float)) and 'bytes' in key.lower():
                    print(f"\033[90m{formatted_key}:\033[0m {self._format_bytes(value)}")
                else:
                    print(f"\033[90m{formatted_key}:\033[0m {value}")
        
    def run(self):
        """Main interactive loop."""
        try:
            while True:
                self.clear_screen()
                self.print_header()
                self.print_menu()
                
                choice = self.get_user_choice(
                    "Enter your choice (1-6): ", 
                    ['1', '2', '3', '4', '5', '6']
                )
                
                if choice == '1':
                    self.parse_file_workflow()
                elif choice == '2':
                    self.query_workflow()
                elif choice == '3':
                    self.list_files_workflow()
                elif choice == '4':
                    self.table_view_workflow()
                elif choice == '5':
                    self.show_plugin_info_workflow()
                elif choice == '6':
                    print("\n\033[92mThank you for using LogSnoop! 👋\033[0m")
                    break
                    
        except KeyboardInterrupt:
            print("\n\n\033[92mThank you for using LogSnoop! 👋\033[0m")


def run_interactive_mode(db_path='logsnoop.db'):
    """Entry point for interactive mode."""
    interactive = LogSnoopInteractive(db_path)
    interactive.run()


if __name__ == '__main__':
    run_interactive_mode()