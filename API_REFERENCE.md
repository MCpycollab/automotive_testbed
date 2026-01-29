# Validation API Reference

The Validation API runs on port **9999** and provides endpoints for checking system status and validating exploit success.

Base URL: `http://localhost:9999`

## Endpoints

### Health Check

```
GET /
```

Simple health check to verify the API is running.

**Response**

```json
{
  "status": "ok"
}
```

**Example**

```bash
curl http://localhost:9999/
```

---

### System Status

```
GET /status
```

Returns comprehensive system status including services, door states, and exploit completion.

**Response**

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | ISO 8601 UTC timestamp |
| `services` | object | Running state of each service |
| `doors` | object | Current door lock states |
| `exploits` | object | Completion status for V1-V8 |

**Services Object**

| Field | Type | Description |
|-------|------|-------------|
| `sshd` | boolean | SSH server running |
| `infotainment` | boolean | Web app running |
| `validation-api` | boolean | This API running |
| `icsim` | boolean | ICSim dashboard running (graphical, requires X11) |
| `controls` | boolean | ICSim controls running (graphical, requires X11) |

> **Note**: The `icsim` and `controls` services provide optional graphical visualization. They may show as `false` in headless mode or if image assets are unavailable. This does not affect CAN bus functionality - challenges V3 and V4 work regardless of ICSim status.

**Doors Object**

| Field | Type | Description |
|-------|------|-------------|
| `fl` | boolean | Front left door unlocked |
| `fr` | boolean | Front right door unlocked |
| `rl` | boolean | Rear left door unlocked |
| `rr` | boolean | Rear right door unlocked |

**Exploits Object**

| Field | Type | Description |
|-------|------|-------------|
| `v1_ssh` | boolean | SSH access achieved |
| `v2_sqli` | boolean | SQL injection successful |
| `v3_doors` | boolean | All doors unlocked |
| `v4_replay` | boolean | CAN replay detected |
| `v5_traversal` | boolean | Directory traversal successful |
| `v6_cmdi` | boolean | Command injection successful |
| `v7_idor` | boolean | IDOR access successful |
| `v8_overflow` | boolean | Buffer overflow detected |

**Example Response**

```json
{
  "timestamp": "2024-01-15T10:30:00.000000Z",
  "services": {
    "sshd": true,
    "infotainment": true,
    "validation-api": true,
    "icsim": true,
    "controls": true
  },
  "doors": {
    "fl": false,
    "fr": false,
    "rl": false,
    "rr": false
  },
  "exploits": {
    "v1_ssh": false,
    "v2_sqli": false,
    "v3_doors": false,
    "v4_replay": false,
    "v5_traversal": false,
    "v6_cmdi": false,
    "v7_idor": false,
    "v8_overflow": false
  }
}
```

**Example**

```bash
curl http://localhost:9999/status | jq
```

---

### Validate Challenge

```
GET /validate/<challenge_id>
```

Validates whether a specific exploit/challenge has been completed.

**Path Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `challenge_id` | string | One of: `ssh_access`, `sqli_success`, `blind_sqli`, `doors_unlocked`, `can_replay`, `directory_traversal`, `command_injection`, `idor`, `buffer_overflow`, `chain_v2_v6` |

**Response**

| Field | Type | Description |
|-------|------|-------------|
| `challenge_id` | string | The requested challenge ID |
| `success` | boolean | Whether the exploit was successful |
| `details` | object | Challenge-specific details |

**Challenge IDs**

| ID | Challenge | Success Condition |
|----|-----------|-------------------|
| `ssh_access` | V1: SSH Access | Active SSH session as admin user |
| `sqli_success` | V2: SQL Injection | SQLi bypass marker found in logs |
| `blind_sqli` | V2-B: Blind SQL Injection | Blind SQLi extraction marker found in logs |
| `doors_unlocked` | V3: Door Control | All four doors report unlocked |
| `can_replay` | V4: CAN Replay | Replay attack marker found in logs |
| `directory_traversal` | V5: Directory Traversal | Traversal attack marker found in gateway logs |
| `command_injection` | V6: Command Injection | Injection marker found in infotainment logs |
| `idor` | V7: IDOR | IDOR access marker found in infotainment logs |
| `buffer_overflow` | V8: Buffer Overflow | Overflow marker in OBD logs or service crashed |
| `chain_v2_v6` | V2→V6 Chain | Both SQLi and command injection successful |

**Details by Challenge**

- **ssh_access**: Returns `active_sessions` array of current SSH sessions
- **sqli_success**: Returns `log_file` path and `sqli_detected` boolean
- **blind_sqli**: Returns `log_file` path and `extraction_detected` boolean
- **doors_unlocked**: Returns `door_states` object with each door's status
- **can_replay**: Returns `log_file` path and `replay_detected` boolean
- **directory_traversal**: Returns `log_file` path and `traversal_detected` boolean
- **command_injection**: Returns `log_file` path and `injection_detected` boolean
- **idor**: Returns `log_file` path and `idor_detected` boolean
- **buffer_overflow**: Returns `log_file` path, `overflow_detected` boolean, and `obd_service_status` string
- **chain_v2_v6**: Returns `log_file` path, `v2_sqli_complete`, `v6_cmdi_complete`, and `chain_complete` booleans

**Example Responses**

```json
// SSH Access Success
{
  "challenge_id": "ssh_access",
  "success": true,
  "details": {
    "active_sessions": ["admin    pts/0        2024-01-15 10:30"]
  }
}

// SQL Injection Success
{
  "challenge_id": "sqli_success",
  "success": true,
  "details": {
    "detection_method": "indirect",
    "description": "Detects SQLi via AUTH_RESULT entries where login succeeded without valid password",
    "log_file": "/var/log/automotive-pentest/infotainment.log",
    "sqli_detected": true
  }
}

// Blind SQL Injection Success (V2-B)
{
  "challenge_id": "blind_sqli",
  "success": true,
  "details": {
    "log_file": "/var/log/automotive-pentest/infotainment.log",
    "extraction_detected": true
  }
}

// Doors Unlocked Success
{
  "challenge_id": "doors_unlocked",
  "success": true,
  "details": {
    "door_states": {
      "fl": true,
      "fr": true,
      "rl": true,
      "rr": true
    }
  }
}

// CAN Replay Success
{
  "challenge_id": "can_replay",
  "success": true,
  "details": {
    "log_file": "/var/log/automotive-pentest/gateway.log",
    "replay_detected": true
  }
}

// Directory Traversal Success (V5)
{
  "challenge_id": "directory_traversal",
  "success": true,
  "details": {
    "log_file": "/var/log/automotive-pentest/gateway.log",
    "traversal_detected": true
  }
}

// Command Injection Success (V6)
{
  "challenge_id": "command_injection",
  "success": true,
  "details": {
    "log_file": "/var/log/automotive-pentest/infotainment.log",
    "injection_detected": true
  }
}

// IDOR Success (V7)
{
  "challenge_id": "idor",
  "success": true,
  "details": {
    "log_file": "/var/log/automotive-pentest/infotainment.log",
    "idor_detected": true
  }
}

// Buffer Overflow Success (V8)
{
  "challenge_id": "buffer_overflow",
  "success": true,
  "details": {
    "log_file": "/var/log/automotive-pentest/obd.log",
    "overflow_detected": true,
    "obd_service_status": "obd                              RUNNING   pid 1234, uptime 0:05:00"
  }
}

// Attack Chain V2→V6 Success
{
  "challenge_id": "chain_v2_v6",
  "success": true,
  "details": {
    "log_file": "/var/log/automotive-pentest/infotainment.log",
    "v2_sqli_complete": true,
    "v6_cmdi_complete": true,
    "chain_complete": true
  }
}
```

**Error Response (404)**

```json
{
  "challenge_id": "invalid_id",
  "success": false,
  "details": {
    "error": "Unknown challenge ID"
  }
}
```

**Examples**

```bash
# Check V1: SSH Access
curl http://localhost:9999/validate/ssh_access | jq

# Check V2: SQL Injection
curl http://localhost:9999/validate/sqli_success | jq

# Check V2-B: Blind SQL Injection
curl http://localhost:9999/validate/blind_sqli | jq

# Check V3: Door Control
curl http://localhost:9999/validate/doors_unlocked | jq

# Check V4: CAN Replay
curl http://localhost:9999/validate/can_replay | jq

# Check V5: Directory Traversal
curl http://localhost:9999/validate/directory_traversal | jq

# Check V6: Command Injection
curl http://localhost:9999/validate/command_injection | jq

# Check V7: IDOR
curl http://localhost:9999/validate/idor | jq

# Check V8: Buffer Overflow
curl http://localhost:9999/validate/buffer_overflow | jq

# Check V2→V6 Attack Chain
curl http://localhost:9999/validate/chain_v2_v6 | jq
```

---

### View Logs

```
GET /logs
```

Returns sanitized log lines from a specified service.

**Query Parameters**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `service` | string | Yes | - | Service name: `gateway`, `infotainment`, or `validation` |
| `lines` | integer | No | 50 | Number of log lines to return (max 1000) |

**Response**

| Field | Type | Description |
|-------|------|-------------|
| `service` | string | The requested service name |
| `lines` | array | Array of sanitized log strings |
| `count` | integer | Number of lines returned |
| `message` | string | (Optional) Status message if log unavailable |

**Supported Services**

| Service | Log File | Description |
|---------|----------|-------------|
| `gateway` | gateway.log | SSH and system gateway logs |
| `infotainment` | infotainment.log | Web application logs |
| `validation` | validation.log | Validation API logs |

**Example Response**

```json
{
  "service": "infotainment",
  "lines": [
    "2024-01-15 10:30:00 INFO: Application started",
    "2024-01-15 10:30:05 INFO: Login attempt for user: admin"
  ],
  "count": 2
}
```

**Error Response (400)**

```json
{
  "error": "Missing required parameter: service",
  "supported_services": ["gateway", "infotainment", "validation"]
}
```

**Examples**

```bash
# Get last 50 lines from gateway log
curl "http://localhost:9999/logs?service=gateway" | jq

# Get last 100 lines from infotainment log
curl "http://localhost:9999/logs?service=infotainment&lines=100" | jq

# Get last 20 lines from validation log
curl "http://localhost:9999/logs?service=validation&lines=20" | jq
```

---

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad request (missing or invalid parameters) |
| 404 | Resource not found (unknown challenge ID) |
| 500 | Server error |

## Notes

- All timestamps are in UTC ISO 8601 format
- Log lines are sanitized to remove sensitive implementation details
- Door states update within 1 second of CAN bus messages
- Exploit status is evaluated in real-time on each request
