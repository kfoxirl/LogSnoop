#!/bin/bash
# Git Setup and Upload Script for LogSnoop
# Run these commands in your terminal from the LogSnoop directory

echo "🚀 Setting up LogSnoop for GitHub upload..."

# 1. Initialize git repository
echo "📁 Initializing git repository..."
git init

# 2. Add all files to staging
echo "📝 Adding files to git..."
git add .

# 3. Create initial commit
echo "💾 Creating initial commit..."
git commit -m "Initial commit: LogSnoop - Python log parser with plugin architecture

Features:
- Plugin-based architecture for multiple log types
- Support for SSH, FTP, HTTP, simple login, and SKY binary logs
- Interactive table view with pagination and filtering
- Comprehensive query system for traffic analysis
- UTC timestamp handling and file deduplication
- CLI interface with rich formatting options"

# 4. Add GitHub remote (REPLACE with your actual GitHub repo URL)
echo "🔗 Adding GitHub remote..."
echo "⚠️  REPLACE 'your-username' with your actual GitHub username:"
echo "git remote add origin https://github.com/your-username/LogSnoop.git"

# 5. Push to GitHub (run after adding remote)
echo "⬆️  Push to GitHub with:"
echo "git branch -M main"
echo "git push -u origin main"

echo "✅ Ready to upload! Follow the steps above."