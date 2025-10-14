\# SecTools MCP Server - Implementation Guide



\## Overview



The SecTools MCP Server provides AI assistants with access to penetration testing tools in a safe, controlled manner for educational security testing.



\## Technical Implementation



\### Architecture



\- \*\*Base Image\*\*: Kali Linux Rolling (provides pre-configured security tools)

\- \*\*Runtime\*\*: Python 3 with FastMCP framework

\- \*\*Execution\*\*: Non-root user with minimal capabilities

\- \*\*Transport\*\*: stdio (standard input/output)



\### Security Tools Included



1\. \*\*nmap\*\* - Network exploration and security auditing

2\. \*\*nikto\*\* - Web server scanner

3\. \*\*sqlmap\*\* - SQL injection testing

4\. \*\*wpscan\*\* - WordPress vulnerability scanner

5\. \*\*dirb\*\* - Web content scanner

6\. \*\*searchsploit\*\* - Exploit database search



\### Input Sanitization



All user inputs are sanitized using the `sanitize\_input()` function which:

\- Removes shell metacharacters (; \& | ` $ ( ) < >)

\- Strips whitespace

\- Prevents command injection attacks



Target validation ensures inputs are valid IP addresses or domain names.



\### Tool Execution Pattern



All tools follow this pattern:

1\. Sanitize and validate inputs

2\. Build command as list (prevents shell injection)

3\. Execute with timeout

4\. Capture and truncate output if needed

5\. Return formatted results with emojis



\### Timeout and Resource Limits



\- Maximum execution time: 300 seconds (5 minutes)

\- Maximum output length: 10,000 characters

\- Non-blocking execution with proper error handling



\## Usage Guidelines for AI Assistants



\### When to Use These Tools



Use these tools when the user:

\- Explicitly requests security testing on their own infrastructure

\- Needs vulnerability assessment of systems they own

\- Wants to learn about security testing (provide educational context)



\### When NOT to Use These Tools



Do NOT use these tools when:

\- Target ownership is unclear or unconfirmed

\- User hasn't explicitly requested security testing

\- Testing third-party systems without permission

\- Intent appears malicious or unauthorized



\### Best Practices



1\. \*\*Always confirm authorization\*\*: Ask user to confirm they own or have permission to test the target

2\. \*\*Start with less invasive scans\*\*: Begin with basic nmap scans before vulnerability tests

3\. \*\*Explain results\*\*: Help interpret findings in educational context

4\. \*\*Recommend next steps\*\*: Suggest appropriate follow-up actions

5\. \*\*Emphasize legal compliance\*\*: Remind users about legal and ethical considerations



\### Example Interaction Flow

