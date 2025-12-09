#!/bin/bash

# ============================================
# CONFIGURATION
# ============================================
API_URL="http://localhost:3000/api"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Hàm in tiêu đề
print_header() {
    echo -e "\n${BLUE}==========================================================${NC}"
    echo -e "${BLUE}👉 $1${NC}"
    echo -e "${BLUE}==========================================================${NC}"
}

# Hàm in kết quả
check_status() {
    local expected=$1
    local actual=$2
    local response=$3

    if [ "$actual" == "$expected" ]; then
        echo -e "${GREEN}✅ PASS (Status: $actual)${NC}"
    else
        echo -e "${RED}❌ FAIL (Expected: $expected, Got: $actual)${NC}"
        echo -e "${YELLOW}Response: $response${NC}"
    fi
}

echo "🚀 STARTING INTEGRATION TEST..."
echo "Waiting for API to be ready..."
sleep 2

# ============================================
# 1. PUBLIC ROUTES
# ============================================
print_header "1. TEST PUBLIC ROUTES"

echo "🔸 [GET] /test/health (Public Access)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/test/health")
check_status 200 "$HTTP_CODE" ""

# ============================================
# 2. AUTHENTICATION - LOGIN
# ============================================
print_header "2. TEST AUTHENTICATION (LOGIN)"

# --- CASE 2.1: Login sai password (401) ---
echo "🔸 [POST] Login thất bại (Sai password)"
RES=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"superadmin", "password":"WRONG_PASSWORD"}')
BODY=$(echo "$RES" | head -n1)
CODE=$(echo "$RES" | tail -n1)
check_status 401 "$CODE" "$BODY"

# --- CASE 2.2: Login Admin thành công (201) ---
echo "🔸 [POST] Login Super Admin (Thành công)"
RES=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"superadmin", "password":"SuperAdmin123!"}')
ADMIN_TOKEN=$(echo "$RES" | head -n1 | jq -r '.result.accessToken')
ADMIN_CODE=$(echo "$RES" | tail -n1)

if [ "$ADMIN_TOKEN" != "null" ] && [ -n "$ADMIN_TOKEN" ]; then
    echo -e "${GREEN}✅ PASS: Got Admin Token${NC}"
else
    echo -e "${RED}❌ FAIL: Could not get Admin Token${NC}"
    exit 1
fi

# --- CASE 2.3: Login User thường thành công (201) ---
echo "🔸 [POST] Login User Thường (Thành công)"
RES=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"user1", "password":"User123!"}')
USER_TOKEN=$(echo "$RES" | head -n1 | jq -r '.result.accessToken')

if [ "$USER_TOKEN" != "null" ]; then
    echo -e "${GREEN}✅ PASS: Got User Token${NC}"
else
    echo -e "${RED}❌ FAIL: Could not get User Token${NC}"
    exit 1
fi

# ============================================
# 3. REGISTER & VALIDATION (Global Pipe)
# ============================================
print_header "3. TEST REGISTER & VALIDATION"

# --- CASE 3.1: Register thiếu field (400 Bad Request) ---
echo "🔸 [POST] Register thiếu password (Test Validation Pipe)"
RES=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"id": 9999, "username": "fail_user"}')
BODY=$(echo "$RES" | head -n1)
CODE=$(echo "$RES" | tail -n1)
check_status 400 "$CODE" "$BODY"
# Kỳ vọng body chứa message lỗi chi tiết từ class-validator

# --- CASE 3.2: Register thành công (201) ---
RANDOM_USER="newuser_$(date +%s)"
echo "🔸 [POST] Register User mới hợp lệ ($RANDOM_USER)"
RES=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d "{\"id\": $(date +%s), \"username\": \"$RANDOM_USER\", \"password\": \"StrongP@ss1\", \"fullName\": \"New User\", \"email\": \"$RANDOM_USER@test.com\"}")
CODE=$(echo "$RES" | tail -n1)
check_status 201 "$CODE" ""

# ============================================
# 4. RBAC & AUTHORIZATION
# ============================================
print_header "4. TEST RBAC (PHÂN QUYỀN)"

# --- CASE 4.1: Không có Token (401 Unauthorized) ---
echo "🔸 [GET] Truy cập API bảo vệ không có Token"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/rbac/roles")
check_status 401 "$CODE" ""

# --- CASE 4.2: User thường vào trang Admin (403 Forbidden) ---
echo "🔸 [GET] User thường truy cập /rbac/roles (Yêu cầu 'rbac:manage')"
RES=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/rbac/roles" \
    -H "Authorization: Bearer $USER_TOKEN")
BODY=$(echo "$RES" | head -n1)
CODE=$(echo "$RES" | tail -n1)
check_status 403 "$CODE" "$BODY"
echo -e "${YELLOW}👉 Note: Nếu thấy message 'Permission denied', hệ thống RBAC hoạt động tốt.${NC}"

# --- CASE 4.3: Admin vào trang Admin (200 OK) ---
echo "🔸 [GET] Admin truy cập /rbac/roles (Đúng quyền)"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$API_URL/rbac/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
check_status 200 "$CODE" ""

# ============================================
# 5. USER MODULE & BUSINESS LOGIC
# ============================================
print_header "5. TEST USER FEATURES"

# --- CASE 5.1: Xem Profile chính mình (200 OK) ---
echo "🔸 [GET] Xem Profile cá nhân"
RES=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users/profile" \
    -H "Authorization: Bearer $USER_TOKEN")
CODE=$(echo "$RES" | tail -n1)
check_status 200 "$CODE" ""

# --- CASE 5.2: Update Profile với dữ liệu rác (400 Bad Request) ---
# Test xem logic update có bị lỗi khi gửi field không định nghĩa
echo "🔸 [PUT] Update Profile gửi field rác (Test Whitelist)"
RES=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/profile" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"hacker_field": "hacking", "bio": "updated"}')
# Nếu whitelist: true, forbidNonWhitelisted: true -> Sẽ trả về 400
CODE=$(echo "$RES" | tail -n1)
check_status 400 "$CODE" "$(echo "$RES" | head -n1)"

# --- CASE 5.3: Update Profile Hợp lệ (200 OK) ---
echo "🔸 [PUT] Update Profile hợp lệ (Update bio)"
RES=$(curl -s -w "\n%{http_code}" -X PUT "$API_URL/users/profile" \
    -H "Authorization: Bearer $USER_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"bio": "I am a developer"}')
CODE=$(echo "$RES" | tail -n1)
check_status 200 "$CODE" ""

# --- CASE 5.4: Get User by ID không tồn tại (404 Not Found) ---
# Test Exception Filter xử lý lỗi UserNotFoundException
echo "🔸 [GET] Tìm user ID 999999 (Test 404)"
RES=$(curl -s -w "\n%{http_code}" -X GET "$API_URL/users/999999" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
CODE=$(echo "$RES" | tail -n1)
check_status 404 "$CODE" "$(echo "$RES" | head -n1)"

print_header "🎉 TEST COMPLETED!"
