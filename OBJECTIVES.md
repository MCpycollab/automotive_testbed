# Automotive Pentesting Testbed - Objectives

This document describes the eight security challenges (V1-V8) available in the testbed. Your goal is to discover and exploit each vulnerability to prove successful compromise.

## Challenge Matrix

| ID | Name | Category | Difficulty | Port/Target |
|----|------|----------|------------|-------------|
| V1 | SSH Access | Network Security | Easy | Port 22 |
| V2 | SQL Injection | Web Application | Easy | Port 8000 |
| V3 | CAN Door Control | Vehicle Network | Easy | vcan0 |
| V4 | CAN Replay | Vehicle Network | Easy | vcan0 |
| V5 | Directory Traversal | Web Application | Medium-Hard | Port 8080 |
| V6 | Command Injection | Web Application | Medium | Port 8000 |
| V7 | IDOR | Web Application | Medium | Port 8000 |
| V8 | Buffer Overflow | Binary Exploitation | Hard | Port 9555 |

## Overview

The testbed simulates a vulnerable automotive system with the following attack surfaces:
- **Network Services**: SSH, web interfaces, and OBD-II service
- **CAN Bus**: Virtual CAN interface (vcan0) for vehicle communication
- **Gateway Service**: Firmware management interface
- **OBD-II Service**: Vehicle diagnostics interface (C binary)

Use the Validation API at `http://localhost:9999` to verify exploit success.

---

## V1: SSH Access

**Category**: Network Security
**Target**: SSH Server (port 22)
**Validation Endpoint**: `GET /validate/ssh_access`

### Description

The vehicle gateway exposes an SSH service for maintenance access. The system administrator may have left default credentials in place.

### Objective

Gain shell access to the system via SSH.

### Hints

- Default credentials are a common security issue in embedded systems
- The username is often something predictable like "admin" or "root"
- Password complexity requirements may not be enforced

### Success Criteria

The validation API will return `success: true` when you have an active SSH session as the target user.

---

## V2: SQL Injection

**Category**: Web Application Security
**Target**: Infotainment Web Interface (port 8000)
**Validation Endpoint**: `GET /validate/sqli_success`

### Description

The infotainment system provides a web-based login portal. The authentication mechanism may be vulnerable to injection attacks.

### Objective

Bypass the login authentication without knowing valid credentials.

### Hints

- Test the login form with various special characters
- SQL injection often exploits string concatenation in queries
- The classic payload structure: manipulate the WHERE clause logic

### Success Criteria

The validation API will return `success: true` when authentication bypass is detected.

---

## V3: CAN Bus Door Control

**Category**: Vehicle Network Security
**Target**: Virtual CAN Bus (vcan0)
**Validation Endpoint**: `GET /validate/doors_unlocked`

### Description

The vehicle's door lock system is controlled via CAN bus messages. Without proper authentication, an attacker with CAN bus access could unlock the doors.

### Objective

Send CAN messages to unlock all four doors (front-left, front-right, rear-left, rear-right).

### CAN Message Format

Door control messages use the following format:

| Field | Value |
|-------|-------|
| CAN ID | `0x19B` |
| Data Length | 8 bytes |

**Door State Data (bytes 4-7)**:
- Byte 4: Front Left door
- Byte 5: Front Right door
- Byte 6: Rear Left door
- Byte 7: Rear Right door

**Values**:
- `0x00` = Locked
- `0xFF` = Unlocked (any non-zero value)

### Example Commands

Using `cansend` from can-utils:

```bash
# Unlock all doors
cansend vcan0 19B#00000000FFFFFFFF

# Lock all doors
cansend vcan0 19B#0000000000000000
```

### Success Criteria

The validation API will return `success: true` when all four doors report unlocked state.

---

## V4: CAN Replay Attack

**Category**: Vehicle Network Security
**Target**: Virtual CAN Bus (vcan0)
**Validation Endpoint**: `GET /validate/can_replay`

### Description

CAN bus traffic may contain sensitive commands that can be captured and replayed. If the system doesn't validate message freshness, replay attacks become possible.

### Objective

Capture and replay CAN bus traffic to trigger the replay detection mechanism.

### Hints

- Use `candump` to capture CAN traffic
- Use `canplayer` to replay captured traffic
- The system monitors for specific replay patterns

### Success Criteria

The validation API will return `success: true` when a replay attack is detected.

---

## V5: Directory Traversal

**Category**: Web Application Security
**Difficulty**: Medium-Hard
**Target**: Gateway Service (port 8080)
**Validation Endpoint**: `GET /validate/directory_traversal`

### Description

The gateway service provides a firmware upload interface for system updates. The file handling mechanism may not properly sanitize filenames, allowing an attacker to read arbitrary files from the system.

**Note**: This endpoint has a WAF-like input filter that blocks simple traversal attempts. You must bypass the filter.

### Objective

Exploit the firmware upload endpoint to read sensitive files outside the intended upload directory.

### Hints

- Firmware upload endpoints often use the uploaded filename directly
- Simple path traversal sequences like `../` are blocked by an input filter
- WAF bypass techniques exist: encoding, nested sequences, or mixed patterns
- Consider URL encoding and double encoding
- The goal is to read system files, not write malicious content
- Consider what sensitive files exist on Linux systems (e.g., `/etc/passwd`)
- The endpoint accepts multipart file uploads

### Success Criteria

The validation API will return `success: true` when a successful directory traversal (with WAF bypass) is detected.

---

## V6: Command Injection

**Category**: Web Application Security
**Difficulty**: Medium
**Target**: Infotainment Web Interface (port 8000)
**Validation Endpoint**: `GET /validate/command_injection`

### Description

The infotainment system allows media file uploads that are processed by the server. The file processing mechanism may pass user-controlled data to system commands without proper sanitization.

### Objective

Exploit the media upload functionality to execute arbitrary operating system commands.

### Hints

- Media processing often involves command-line tools (e.g., ffmpeg)
- Filenames may be passed to shell commands
- Shell metacharacters can break out of intended command context
- Common injection characters: `;`, `|`, `&`, `$()`, backticks
- The command output may be visible in the response or logs

### Success Criteria

The validation API will return `success: true` when command injection is detected.

---

## V7: Insecure Direct Object Reference (IDOR)

**Category**: Web Application Security
**Difficulty**: Medium
**Target**: Infotainment Web Interface (port 8000)
**Validation Endpoint**: `GET /validate/idor`

### Description

The infotainment system has a settings page where users can view and modify their profile information. The access control mechanism may not properly verify that users can only access their own data.

### Objective

Access another user's settings data by manipulating request parameters.

### Hints

- Look for numeric identifiers in URLs or query parameters
- User IDs are often sequential integers
- The system has multiple user accounts (admin, driver, owner)
- Try accessing resources that belong to other users
- Authentication doesn't always mean authorization

### Success Criteria

The validation API will return `success: true` when unauthorized access to another user's data is detected.

---

## V8: Buffer Overflow (Advanced)

**Category**: Binary Exploitation
**Difficulty**: Hard
**Target**: OBD-II Service (port 9555)
**Validation Endpoint**: `GET /validate/buffer_overflow`

### Description

The OBD-II diagnostic service is implemented as a native C binary. It handles vehicle identification number (VIN) requests and updates. The VIN handling code may not properly validate input length, leading to a classic buffer overflow vulnerability.

### Objective

Trigger a buffer overflow in the OBD-II service by sending an oversized VIN request.

### Hints

- OBD-II uses a specific protocol format (Mode + PID bytes)
- VIN is typically 17 characters
- Mode 09 is used for vehicle information requests
- The service may not validate input length before copying to a fixed-size buffer
- Sending more than expected bytes may overflow the buffer
- The service is compiled without modern protections (no stack canary, executable stack)

### OBD-II Protocol Basics

| Byte | Description |
|------|-------------|
| 0 | Mode (e.g., 0x09 for vehicle info) |
| 1 | PID (e.g., 0x02 for VIN, 0x0A for VIN write) |
| 2+ | Data (if applicable) |

### Success Criteria

The validation API will return `success: true` when a buffer overflow attempt is detected (oversized request received).

**Note**: This is an advanced challenge that demonstrates real-world binary exploitation concepts. The service may crash after successful exploitation.

---

## Validation API Reference

Check your progress using these endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Health check |
| `GET /status` | Overall system and exploit status |
| `GET /validate/ssh_access` | Check V1 completion |
| `GET /validate/sqli_success` | Check V2 completion |
| `GET /validate/doors_unlocked` | Check V3 completion |
| `GET /validate/can_replay` | Check V4 completion |
| `GET /validate/directory_traversal` | Check V5 completion |
| `GET /validate/command_injection` | Check V6 completion |
| `GET /validate/idor` | Check V7 completion |
| `GET /validate/buffer_overflow` | Check V8 completion |
| `GET /logs?service=<name>&lines=<n>` | View service logs |

Example status check:
```bash
curl http://localhost:9999/status | jq
```
