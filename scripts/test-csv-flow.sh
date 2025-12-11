#!/bin/bash

# ============================================
# CẤU HÌNH
# ============================================
API_URL="http://localhost:3000/api"
CSV_FILE="rbac_rules.csv"

# Màu sắc
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================
# 1. ĐĂNG NHẬP
# ============================================
echo -e "${BLUE}🚀 BƯỚC 1: Đăng nhập Super Admin...${NC}"

LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"superadmin", "password":"SuperAdmin123!"}')

# --- FIX Ở ĐÂY: Thêm .result trước .accessToken ---
TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.result.accessToken')

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
  echo -e "${RED}❌ Đăng nhập thất bại!${NC}"
  echo "Response: $LOGIN_RESPONSE"
  exit 1
fi

echo -e "${GREEN}✅ Đăng nhập thành công!${NC}"
echo "🔑 Token: ${TOKEN:0:20}..."

# ============================================
# 2. DOWNLOAD CSV (EXPORT)
# ============================================
echo -e "\n${BLUE}🚀 BƯỚC 2: Download RBAC Rules (Export)...${NC}"

# Lưu ý: API trả về stream file, không phải JSON bọc trong interceptor
HTTP_CODE=$(curl -s -w "%{http_code}" -X GET "$API_URL/rbac/data/export" \
  -H "Authorization: Bearer $TOKEN" \
  -o "$CSV_FILE")

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "201" ]; then
  echo -e "${GREEN}✅ Download thành công! File: $CSV_FILE${NC}"
  echo "📄 5 dòng đầu tiên:"
  head -n 5 "$CSV_FILE"
else
  echo -e "${RED}❌ Download thất bại! HTTP Code: $HTTP_CODE${NC}"
  cat "$CSV_FILE"
  exit 1
fi

# ============================================
# 3. EDIT CSV
# ============================================
echo -e "\n${BLUE}🚀 BƯỚC 3: Thêm quyền test vào CSV...${NC}"
echo "TEST_ROLE,test_resource,create,*,Quyền test tự động" >> "$CSV_FILE"
echo -e "${GREEN}✅ Đã sửa file CSV.${NC}"

# ============================================
# 4. UPLOAD CSV (IMPORT)
# ============================================
echo -e "\n${BLUE}🚀 BƯỚC 4: Upload CSV (Import)...${NC}"

IMPORT_RESPONSE=$(curl -s -X POST "$API_URL/rbac/data/import" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$CSV_FILE")

echo "Import Response:"
echo "$IMPORT_RESPONSE" | jq .

# ============================================
# 5. DỌN DẸP
# ============================================
echo -e "\n${BLUE}🧹 Dọn dẹp...${NC}"
rm "$CSV_FILE"
echo -e "${GREEN}✨ DONE!${NC}"
