#!/bin/sh
API_URL="http://localhost:${PORT:-8080}/api/test/health"

# Thêm -f (fail on HTTP error) và --max-time 5 (timeout 5s chống treo)
STATUS=$(curl -s -f -o /dev/null -w "%{http_code}" --max-time 5 "$API_URL")

if [ "$STATUS" = "200" ]; then
    exit 0
else
    echo "Healthcheck failed with status: $STATUS"
    exit 1
fi