#!/bin/bash

# Cấu hình
API_URL="http://localhost:3000/api"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "======================================================="
echo "🧪 BẮT ĐẦU TEST HỆ THỐNG RBAC NESTJS"
echo "======================================================="

# 1. Test Health Check (Public)
echo -e "\n${GREEN}[1] Kiểm tra Health Check (Ai cũng vào được)${NC}"
curl -s "$API_URL/test/health" | jq .

# 2. Đăng nhập SUPER ADMIN
echo -e "\n${GREEN}[2] Đăng nhập SUPER ADMIN (Full quyền)${NC}"
ADMIN_RES=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"superadmin","password":"SuperAdmin123!"}')

ADMIN_TOKEN=$(echo $ADMIN_RES | jq -r '.accessToken')

if [ "$ADMIN_TOKEN" == "null" ]; then
  echo -e "${RED}❌ Đăng nhập Admin thất bại! Kiểm tra lại DB/Seeder.${NC}"
  exit 1
else
  echo -e "✅ Đăng nhập Admin thành công!"
fi

# 3. Đăng nhập USER THƯỜNG
echo -e "\n${GREEN}[3] Đăng nhập USER THƯỜNG (Quyền hạn chế)${NC}"
USER_RES=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"User123!"}')

USER_TOKEN=$(echo $USER_RES | jq -r '.accessToken')

if [ "$USER_TOKEN" == "null" ]; then
  echo -e "${RED}❌ Đăng nhập User thất bại!${NC}"
  exit 1
else
  echo -e "✅ Đăng nhập User thành công!"
fi

# 4. Test Quyền Admin (Vào trang quản lý Role)
echo -e "\n${GREEN}[4] Test: Admin truy cập API quản lý Role (Yêu cầu 'rbac:manage')${NC}"
echo "👉 Admin đang truy cập..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$API_URL/rbac/roles" -H "Authorization: Bearer $ADMIN_TOKEN")

if [ "$HTTP_CODE" == "200" ]; then
  echo -e "✅ KẾT QUẢ: 200 OK -> Admin được phép vào. (ĐÚNG)"
else
  echo -e "${RED}❌ KẾT QUẢ: $HTTP_CODE -> Admin bị chặn. (SAI)${NC}"
fi

# 5. Test User cố tình vào trang Admin (Cái hay nằm ở đây)
echo -e "\n${GREEN}[5] Test: User thường cố tình truy cập API quản lý Role${NC}"
echo "👉 User đang truy cập..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$API_URL/rbac/roles" -H "Authorization: Bearer $USER_TOKEN")

if [ "$HTTP_CODE" == "403" ]; then
  echo -e "✅ KẾT QUẢ: 403 FORBIDDEN -> User bị đá đít ra ngoài. (ĐÚNG - Hệ thống bảo mật tốt)"
else
  echo -e "${RED}❌ KẾT QUẢ: $HTTP_CODE -> User vào được. (SAI - Lỗ hổng bảo mật!)${NC}"
fi

# 6. Test User xem profile chính mình
echo -e "\n${GREEN}[6] Test: User xem Profile của mình${NC}"
curl -s -X GET "$API_URL/users/profile" -H "Authorization: Bearer $USER_TOKEN" | jq .

echo -e "\n======================================================="
echo "🎉 HOÀN TẤT TEST"
echo "======================================================="
