# LogSnoop Makefile
# Simple installation and maintenance tasks

.PHONY: help install uninstall install-user install-system test clean man

PREFIX ?= /usr/local
USER_PREFIX = $(HOME)/.local

help:
	@echo "LogSnoop Installation Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install-user    Install LogSnoop for current user (default: ~/.local)"
	@echo "  install-system  Install LogSnoop system-wide (requires sudo)"
	@echo "  install         Alias for install-user"
	@echo "  uninstall       Remove LogSnoop installation"
	@echo "  test           Run basic functionality tests"
	@echo "  man            View the manual page"
	@echo "  clean          Clean up temporary files"
	@echo ""
	@echo "Usage examples:"
	@echo "  make install-user"
	@echo "  sudo make install-system"
	@echo "  make install PREFIX=/opt/logsnoop"

install: install-user

install-user:
	@echo "Installing LogSnoop for current user..."
	@./install.sh $(USER_PREFIX)

install-system:
	@echo "Installing LogSnoop system-wide..."
	@./install.sh $(PREFIX)

uninstall:
	@echo "Uninstalling LogSnoop..."
	@if [ -f "$(PREFIX)/bin/logsnoop" ]; then \
		echo "Removing system installation..."; \
		rm -f $(PREFIX)/bin/logsnoop; \
		rm -f $(PREFIX)/share/man/man1/logsnoop.1; \
		rm -rf $(PREFIX)/share/logsnoop; \
		echo "System installation removed."; \
	elif [ -f "$(USER_PREFIX)/bin/logsnoop" ]; then \
		echo "Removing user installation..."; \
		rm -f $(USER_PREFIX)/bin/logsnoop; \
		rm -f $(USER_PREFIX)/share/man/man1/logsnoop.1; \
		rm -rf $(USER_PREFIX)/share/logsnoop; \
		echo "User installation removed."; \
	else \
		echo "No LogSnoop installation found."; \
	fi

test:
	@echo "Running basic LogSnoop tests..."
	@python3 cli.py --help >/dev/null && echo "✅ CLI help works"
	@python3 cli.py list-plugins >/dev/null && echo "✅ Plugin listing works"
	@echo "Basic tests completed successfully!"

man:
	@if command -v man >/dev/null 2>&1; then \
		man ./logsnoop.1; \
	else \
		echo "man command not found. Manual page content:"; \
		cat logsnoop.1; \
	fi

clean:
	@echo "Cleaning up temporary files..."
	@find . -name "*.pyc" -delete
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@rm -f *.log *.db
	@echo "Cleanup complete."

.PHONY: check-requirements
check-requirements:
	@echo "Checking system requirements..."
	@python3 --version || (echo "❌ Python 3 is required" && exit 1)
	@echo "✅ Python 3 found"
	@which pip3 >/dev/null || (echo "❌ pip3 is required" && exit 1)
	@echo "✅ pip3 found"
	@echo "System requirements satisfied."