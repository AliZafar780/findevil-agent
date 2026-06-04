# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.1.x   | ✅ Active          |
| < 2.0   | ❌ Not supported   |

## Reporting a Vulnerability

FindEvil Agent is a digital forensics tool designed for authorized security testing.
If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public GitHub issue
2. Email the maintainer directly
3. Include detailed steps to reproduce
4. Include potential impact assessment

## Security Architecture

FindEvil Agent employs defense-in-depth:

| Layer | Protection |
|-------|-----------|
| Path Validation | All evidence paths validated against `EVIDENCE_ROOT` |
| Input Sanitization | Null bytes, control chars, and path traversal blocked |
| Type Safety | Pydantic models enforce parameter types |
| Audit Trail | Every tool call logged with arguments and result |
| Concurrent Safety | `asyncio.Lock` prevents interleaved responses |
| Output Isolation | Tool output limited to `MAX_OUTPUT_CHARS` |
| Timeout Bounds | Tool execution capped at `MAX_TIMEOUT` |

## Attack Vectors Blocked

- Path traversal (9 variants)
- Null byte injection
- Symlink swap attacks
- Output directory escape (10 system directories)
- Command injection via YARA rules
- Wrong parameter types
- Missing required parameters
- Empty YARA rules
- Malformed input
- Resource exhaustion (200MB+ input)
- Log injection
- TOCTOU race conditions
