"""
Demo implementation of LogSnoop Interactive Mode
This shows how an interactive interface could be structured.
"""

import os
import sys
from pathlib import Path
from logsnoop.core import LogParser


class InteractiveMode:
    def __init__(self, db_path='logsnoop.db'):
        self.log_parser = LogParser(db_path)
        self.db_path = db_path
        
    def clear_screen(self):
        """Clear terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_header(self):
        """Print LogSnoop header."""
        print("╔══════════════════════════════════════════╗")
        print("║           LogSnoop Interactive           ║") 
        print("║      Log Analysis Made Simple            ║")
        print("╚══════════════════════════════════════════╝")
        print()
        
    def print_menu(self):
        """Print main menu."""
        print("┌─────────────────────────────────────────┐")
        print("│ What would you like to do?              │")
        print("├─────────────────────────────────────────┤")
        print("│ 1. Parse a new log file                 │")
        print("│ 2. Query existing data                  │") 
        print("│ 3. View parsed files                    │")
        print("│ 4. Browse log entries (table view)     │")
        print("│ 5. Show plugin information              │")
        print("│ 6. Exit                                 │")
        print("└─────────────────────────────────────────┘")
        print()
        
    def get_user_choice(self, prompt, valid_choices):
        """Get validated user input."""
        while True:
            try:
                choice = input(prompt).strip()
                if choice in valid_choices:
                    return choice
                print(f"Invalid choice. Please select from: {', '.join(valid_choices)}")
            except (KeyboardInterrupt, EOFError):
                print("\nGoodbye!")
                sys.exit(0)
                
    def select_plugin(self, purpose="use"):
        """Interactive plugin selection."""
        plugins = self.log_parser.get_available_plugins()
        
        print(f"\n🔌 Available Plugins ({purpose}):")
        print("─" * 50)
        
        for i, plugin_name in enumerate(plugins, 1):
            plugin = self.log_parser.plugins[plugin_name]
            print(f"{i}. {plugin_name}")
            print(f"   📝 {plugin.description}")
            print()
            
        choice = self.get_user_choice(
            f"Select plugin (1-{len(plugins)}) or 'b' for back: ",
            [str(i) for i in range(1, len(plugins) + 1)] + ['b']
        )
        
        if choice == 'b':
            return None
            
        return list(plugins)[int(choice) - 1]
        
    def select_file_path(self):
        """Interactive file selection."""
        print("\n📁 File Selection:")
        print("─" * 30)
        
        while True:
            file_path = input("Enter log file path (or 'b' for back): ").strip()
            
            if file_path == 'b':
                return None
                
            if not file_path:
                print("Please enter a file path.")
                continue
                
            path = Path(file_path)
            if not path.exists():
                print(f"❌ File not found: {file_path}")
                continue
                
            if not path.is_file():
                print(f"❌ Path is not a file: {file_path}")
                continue
                
            return str(path.absolute())
            
    def parse_file_workflow(self):
        """Guided file parsing workflow."""
        self.clear_screen()
        self.print_header()
        print("🔍 Parse New Log File")
        print("=" * 40)
        
        # Select plugin
        plugin_name = self.select_plugin("parse files")
        if not plugin_name:
            return
            
        # Select file
        file_path = self.select_file_path()
        if not file_path:
            return
            
        # Show confirmation
        print(f"\n📋 Parsing Configuration:")
        print(f"   📄 File: {file_path}")
        print(f"   🔌 Plugin: {plugin_name}")
        
        confirm = self.get_user_choice(
            "\nProceed with parsing? (y/n): ", ['y', 'n']
        )
        
        if confirm == 'y':
            try:
                print("\n⏳ Parsing file...")
                result = self.log_parser.parse_log_file(file_path, plugin_name)
                print(f"\n✅ Successfully parsed {result['entries_count']} entries!")
                print(f"📊 File ID: {result['file_id']}")
                
                # Offer to show summary
                show_summary = self.get_user_choice(
                    "\nWould you like to see a summary? (y/n): ", ['y', 'n']
                )
                
                if show_summary == 'y':
                    summary = self.log_parser.get_file_summary(result['file_id'])
                    self.display_summary(summary)
                    
            except Exception as e:
                print(f"\n❌ Error parsing file: {e}")
                
        input("\nPress Enter to continue...")
        
    def query_workflow(self):
        """Guided query workflow."""
        self.clear_screen()
        self.print_header()
        print("🔎 Query Log Data")
        print("=" * 40)
        
        # Check if we have any parsed files
        files = self.log_parser.list_parsed_files()
        if not files:
            print("❌ No parsed files found. Please parse a log file first.")
            input("Press Enter to continue...")
            return
            
        # Select plugin
        plugin_name = self.select_plugin("query")
        if not plugin_name:
            return
            
        # Load plugin and show queries
        plugin = self.log_parser.plugins[plugin_name]
        queries = list(plugin.supported_queries)
        
        print(f"\n📊 Available Queries for {plugin_name}:")
        print("─" * 50)
        
        for i, query in enumerate(queries, 1):
            # You could add query descriptions here
            print(f"{i}. {query}")
            
        choice = self.get_user_choice(
            f"\nSelect query (1-{len(queries)}) or 'b' for back: ",
            [str(i) for i in range(1, len(queries) + 1)] + ['b']
        )
        
        if choice == 'b':
            return
            
        query_type = queries[int(choice) - 1]
        
        # Execute query
        try:
            print(f"\n⏳ Executing query: {query_type}")
            results = self.log_parser.query_logs(plugin_name, query_type)
            
            print(f"\n✅ Query completed!")
            print("=" * 50)
            
            # Display results (simplified)
            if isinstance(results, dict):
                for key, value in results.items():
                    print(f"{key}: {value}")
            elif isinstance(results, list):
                for item in results[:10]:  # Show first 10
                    print(item)
                if len(results) > 10:
                    print(f"... and {len(results) - 10} more results")
            else:
                print(results)
                
        except Exception as e:
            print(f"\n❌ Error executing query: {e}")
            
        input("\nPress Enter to continue...")
        
    def list_files_workflow(self):
        """Show parsed files."""
        self.clear_screen()
        self.print_header()
        print("📁 Parsed Files")
        print("=" * 40)
        
        files = self.log_parser.list_parsed_files()
        
        if not files:
            print("No parsed files found.")
        else:
            for file_info in files:
                print(f"ID: {file_info['id']}")
                print(f"📄 File: {file_info['file_path']}")
                print(f"🔌 Plugin: {file_info['plugin_name']}")
                print(f"📊 Entries: {file_info['entry_count']:,}")
                print(f"📅 Parsed: {file_info['created_at']}")
                print("─" * 50)
                
        input("\nPress Enter to continue...")
        
    def display_summary(self, summary):
        """Display file summary in a nice format."""
        print("\n📊 File Summary:")
        print("─" * 30)
        for key, value in summary.items():
            if key != 'id':  # Skip internal ID
                print(f"{key.replace('_', ' ').title()}: {value}")
        
    def run(self):
        """Main interactive loop."""
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
                print("\n🚧 Table view integration would go here...")
                input("Press Enter to continue...")
            elif choice == '5':
                print("\n🚧 Plugin information would go here...")
                input("Press Enter to continue...")
            elif choice == '6':
                print("\nGoodbye! 👋")
                break


if __name__ == '__main__':
    interactive = InteractiveMode()
    interactive.run()