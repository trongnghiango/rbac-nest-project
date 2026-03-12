#!/bin/sh
# Gọi thẳng vào API Healthcheck bạn đã viết trong TestController
# Chấp nhận localhost hoặc tên container
API_URL="http://localhost:${PORT:-8080}/api/test/health"

# curl lấy HTTP status code
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL")

if [ "$STATUS" = "200" ]; then
    exit 0
else
    echo "Healthcheck failed with status: $STATUS"
    exit 1
fi
