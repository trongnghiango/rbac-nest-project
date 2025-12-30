#!/bin/sh
# Kiểm tra đơn giản qua cổng PORT
nc -z localhost ${PORT:-8080} || exit 1
