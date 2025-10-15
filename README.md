# MPC-Linux-Hack-tools-containers-
Idea from Networkchuck on youtube. Make with some help of AI. Version 0.8. Files need to download: CLAUDE.md, Dockerfile.txt, InstructionforAI.txt, catalog.json, requirements.txt, sectools_server.py
# 🛡️ MCP Security Tools — AI-Powered Pentesting via Docker

**Author:** Hannah  
**Project first made:** October 14, 2025 🎉

## 🚀 Overview

This project is a lightweight AI-integrated penetration testing system built with Docker and connected via the Model Context Protocol (MCP).  
You can interact with an AI agent to run tools like `nmap`, `sqlmap`, `nikto`, and receive real-time scan results from inside the container.

## 🧰 Technologies Used

- 🐳 Docker (for containerizing security tools)
- 🔌 MCP Gateway (to connect AI agents with tools)
- 🤖 AI Agent (Claude, Cursor,...)
- 🛠️ Pentesting tools:
  - `nmap_scan`
  - `sqlmap_test`
  - `nikto_scan`
  - `whois_lookup`
  - `dns_enum`
  - `hydra_brute`
  - `john_hash_crack`
  - `hashcat`
  - and others too ! 

## 📦 How to Run

```bash
# Start the MCP container
docker run -d --name sectools-mcp sectools-mcp-server

# Launch the MCP gateway
docker mcp gateway run

# Register the container
docker mcp server enable sectools-mcp
