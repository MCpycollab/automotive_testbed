#!/bin/bash
#
# health_check.sh - Docker health check for automotive pentesting testbed
#
# Validates that all required services are running and responding.
# Used by Docker HEALTHCHECK to report container health status.
#
# Exit codes:
#   0 - Healthy (all services running)
#   1 - Unhealthy (one or more services failed)
#

# Check required services via supervisorctl
REQUIRED_SERVICES="sshd validation-api infotainment gateway"
for service in $REQUIRED_SERVICES; do
    if ! supervisorctl status "$service" 2>/dev/null | grep -q "RUNNING"; then
        echo "UNHEALTHY: $service is not running"
        exit 1
    fi
done

# Check validation API responds (core service for exploit detection)
if ! curl -sf http://localhost:9999/ >/dev/null 2>&1; then
    echo "UNHEALTHY: Validation API not responding"
    exit 1
fi

# Check infotainment app responds (target for V2 SQLi exploit)
if ! curl -sf http://localhost:8000/ >/dev/null 2>&1; then
    echo "UNHEALTHY: Infotainment app not responding"
    exit 1
fi

# Check gateway app responds (target for V5 directory traversal exploit)
if ! curl -sf http://localhost:8080/ >/dev/null 2>&1; then
    echo "UNHEALTHY: Gateway app not responding"
    exit 1
fi

# OBD service check is optional - it may crash during buffer overflow exploitation (V8)
# We only warn if it's down, but don't fail the health check
if ! supervisorctl status obd 2>/dev/null | grep -q "RUNNING"; then
    echo "WARNING: OBD service not running (may be expected during V8 exploitation)"
    # Don't exit 1 here - OBD is optional
fi

# All checks passed
exit 0
