# Dependency Vulnerability Bot for GitHub

A lightweight GitHub bot that automatically scans dependencies for known vulnerabilities and comments on pull requests.

## ✨ Features

- 🔍 **Auto-scan** on every pull request
- 📦 **Supports** npm and pip packages
- 💬 **Comments** with vulnerability details and fix suggestions
- 🚀 **Easy setup** with minimal configuration
- 💾 **Caching** for faster subsequent scans
- 🐳 **Docker ready** for easy deployment

## 📋 Prerequisites

- Node.js 18+
- GitHub App with webhook permissions
- (Optional) Docker for containerized deployment

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dependency-bot.git
cd dependency-bot

# Install dependencies
npm install

# Run setup
npm run setup