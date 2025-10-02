#!/bin/bash
# LogSnoop Installation Script
# Installs LogSnoop as a system command with man page

set -e  # Exit on any error

INSTALL_PREFIX="${1:-/usr/local}"
LOGSNOOP_DIR="$INSTALL_PREFIX/share/logsnoop"
BIN_DIR="$INSTALL_PREFIX/bin"
MAN_DIR="$INSTALL_PREFIX/share/man/man1"

echo "🚀 Installing LogSnoop..."
echo "Installation prefix: $INSTALL_PREFIX"

# Check if running as root for system-wide installation
if [[ "$INSTALL_PREFIX" == "/usr"* ]] && [[ $EUID -ne 0 ]]; then
    echo "❌ Error: System-wide installation requires root privileges"
    echo "Run with sudo: sudo ./install.sh"
    echo "Or install to user directory: ./install.sh ~/.local"
    exit 1
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p "$LOGSNOOP_DIR"
mkdir -p "$BIN_DIR"
mkdir -p "$MAN_DIR"

# Copy LogSnoop files
echo "📋 Copying LogSnoop files..."
cp -r logsnoop "$LOGSNOOP_DIR/"
cp cli.py "$LOGSNOOP_DIR/"
cp requirements.txt "$LOGSNOOP_DIR/"
cp README.md "$LOGSNOOP_DIR/"
cp -r bin "$LOGSNOOP_DIR/"

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
if [[ -f "$LOGSNOOP_DIR/.venv/bin/activate" ]]; then
    echo "Using existing virtual environment..."
else
    echo "Creating virtual environment..."
    cd "$LOGSNOOP_DIR"
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    cd - > /dev/null
fi

# Install binary wrapper
echo "🔗 Installing binary wrapper..."
cp bin/logsnoop "$BIN_DIR/logsnoop"
chmod +x "$BIN_DIR/logsnoop"

# Install man page
echo "📖 Installing man page..."
cp logsnoop.1 "$MAN_DIR/logsnoop.1"
if command -v mandb >/dev/null 2>&1; then
    echo "Updating man database..."
    mandb -q "$INSTALL_PREFIX/share/man" 2>/dev/null || true
fi

# Set permissions
echo "🔒 Setting permissions..."
chmod -R 755 "$LOGSNOOP_DIR"
chmod 644 "$MAN_DIR/logsnoop.1"

echo "✅ LogSnoop installed successfully!"
echo ""
echo "📋 Installation Summary:"
echo "  • LogSnoop files: $LOGSNOOP_DIR"
echo "  • Binary wrapper: $BIN_DIR/logsnoop"
echo "  • Man page: $MAN_DIR/logsnoop.1"
echo ""
echo "🎯 Usage:"
echo "  • Run: logsnoop --help"
echo "  • Read manual: man logsnoop"
echo "  • List plugins: logsnoop list-plugins"
echo ""

# Check if binary is in PATH
if command -v logsnoop >/dev/null 2>&1; then
    echo "✅ LogSnoop is ready to use!"
    echo "🚀 Try: logsnoop list-plugins"
else
    echo "⚠️  Note: $BIN_DIR is not in your PATH"
    echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
    echo "export PATH=\"$BIN_DIR:\$PATH\""
fi