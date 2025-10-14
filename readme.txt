# SecTools MCP Server

A Model Context Protocol (MCP) server that provides secure access to penetration testing tools for educational purposes on your own infrastructure.

## Purpose

This MCP server provides a secure interface for AI assistants to assist with security testing and vulnerability assessment using industry-standard tools from Kali Linux.

⚠️ **IMPORTANT**: This server is for EDUCATIONAL PURPOSES ONLY. Only use these tools on systems you own or have explicit written permission to test. Unauthorized security testing is illegal.

## Features

### Current Implementation

- **`nmap_scan`** - Network scanning with various scan types (quick, full, service, vuln)
- **`nikto_scan`** - Web server vulnerability scanning
- **`sqlmap_test`** - SQL injection testing on web parameters
- **`wpscan_scan`** - WordPress security scanning and enumeration
- **`dirb_scan`** - Hidden directory and file discovery
- **`searchsploit_lookup`** - Search exploitdb for known vulnerabilities
- **`port_scan_basic`** - Quick TCP port scanning
- **`get_tool_info`** - Display information about available tools

### Security Features

- Input sanitization to prevent command injection
- Non-root execution with minimal capabilities
- Timeout limits to prevent resource exhaustion
- Output length limits to prevent overwhelming responses
- Container isolation for safe operation

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Systems you own or have permission to test

## Installation

See the step-by-step instructions provided with the files.

## Usage Examples

In Claude Desktop, you can ask:

- "Scan 192.168.1.100 for open ports using nmap"
- "Run a nikto scan on http://testserver.local"
- "Check for SQL injection on http://testsite.local/page.php?id=1"
- "Scan my WordPress site at http://myblog.local for vulnerabilities"
- "Search exploitdb for Apache 2.4 vulnerabilities"
- "Find hidden directories on http://testserver.local"
- "What security tools are available?"

## Architecture