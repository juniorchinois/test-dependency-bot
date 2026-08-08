# Dependency Vulnerability Bot for GitHub

[![Test Dependency Bot](https://github.com/yourusername/dependency-bot/actions/workflows/test.yml/badge.svg)](https://github.com/yourusername/dependency-bot/actions/workflows/test.yml)
[![npm version](https://img.shields.io/npm/v/@juniorchinois/depscan.svg)](https://www.npmjs.com/package/@juniorchinois/depscan)
[![codecov](https://codecov.io/gh/yourusername/dependency-bot/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/dependency-bot)

A lightweight, professional GitHub bot that automatically scans dependencies for known vulnerabilities and comments on pull requests.

## ✨ Features

- 🔍 **Auto-scan** on every pull request
- 📦 **Supports** npm and pip packages (more coming)
- 💬 **Comments** with vulnerability details and fix suggestions
- 🚀 **Easy setup** with minimal configuration
- 💾 **Caching** for faster subsequent scans
- 🐳 **Docker ready** for easy deployment
- 📊 **Check runs** integration with GitHub Actions
- ⚡ **Severity filtering** (CRITICAL, HIGH, MEDIUM, LOW)
- 🔧 **CLI tool** for local dependency scanning
- 🛡️ **Ignored packages** support
- 🔄 **Manual scan** via `/scan` comment

## 📋 Prerequisites

- Node.js 18+ or Docker
- GitHub App with webhook permissions
- (Optional) smee.io for local development

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/dependency-bot.git
cd dependency-bot

# Install dependencies
npm install

# Run interactive setup
npm run setup

# Start the bot
npm start