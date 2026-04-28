# 🚀 TÀI LIỆU API HỆ THỐNG STAX (API DOCUMENTATION)

Tài liệu này liệt kê các điểm cuối (endpoints) quan trọng của hệ thống STAX, mô tả mục đích sử dụng và các ví dụ minh họa.

---

## 1. MÔ ĐUN: XÁC THỰC (AUTHENTICATION)
**Prefix:** `/auth`

### 🔑 Đăng nhập (Login)
*   **Endpoint:** `POST /auth/login`
*   **Mô tả:** Đăng nhập vào hệ thống để lấy Access Token và Refresh Token.
*   **Body (JSON):**
    ```json
    {
      "username": "admin",
      "password": "strongPassword123"
    }
    ```
*   **Ví dụ (curl):**
    ```bash
    curl -X POST http://api.stax.com/auth/login -H "Content-Type: application/json" -d '{"username":"user", "password":"pass"}'
    ```

### 👤 Thông tin cá nhân (Profile)
*   **Endpoint:** `GET /auth/profile`
*   **Mô tả:** Lấy thông tin chi tiết của người dùng đang đăng nhập.
*   **Header:** `Authorization: Bearer <Access_Token>`
*   **Ví dụ (Response):**
    ```json
    {
      "id": 1,
      "username": "admin",
      "email": "admin@stax.vn",
      "fullName": "System Admin"
    }
    ```
*   **Ví dụ (curl):**
    ```bash
    curl -X GET http://api.stax.com/auth/profile \
      -H "Authorization: Bearer <Your_Access_Token>"
    ```

### 🔄 Làm mới Token (Refresh Token)
*   **Body:** `{"refreshToken": "string"}`
*   **Ví dụ (curl):**
    ```bash
    curl -X POST http://api.stax.com/auth/refresh \
      -H "Content-Type: application/json" \
      -d '{"refreshToken": "eyJhbG..."}'
    ```

---

## 2. MÔ ĐUN: CRM (QUẢN LÝ KHÁCH HÀNG & BÁN HÀNG)
**Prefix:** `/crm/leads`

### 📥 Tiếp nhận Lead thông minh (Intake)
*   **Endpoint:** `POST /crm/leads/intake`
*   **Mô tả:** Nhập dữ liệu khách hàng tiềm năng mới. Hệ thống sẽ tự động kiểm tra trùng lặp qua SĐT.
*   **Body (JSON):**
    ```json
    {
      "fullName": "Nguyễn Văn A",
      "phone": "0912345678",
      "serviceDemand": "Tư vấn doanh nghiệp",
      "source": "ZALO",
      "notes": "Muốn đăng ký gói Retainer"
    }
    ```
*   **Ví dụ (curl):**
    ```bash
    curl -X POST http://api.stax.com/crm/leads/intake \
      -H "Authorization: Bearer <Access_Token>" \
      -H "Content-Type: application/json" \
      -d '{
        "fullName": "Nguyễn Văn A",
        "phone": "0912345678",
        "serviceDemand": "Tư vấn",
        "source": "DIRECT"
      }'
    ```

### 🏆 Chốt Hợp đồng (Close Won)
*   **Endpoint:** `POST /crm/leads/:id/won`
*   **Mô tả:** Chuyển đổi Lead thành Hợp đồng thực tế. Một quy trình Orchestration phức tạp sẽ diễn ra ngầm (Tạo Org, tạo Hợp đồng, gán Team).
*   **Path Param:** `id` - ID của Lead.
*   **Body (JSON):**
    ```json
    {
      "contractNumber": "HD-2024-001",
      "feeAmount": 12000000,
      "serviceType": "RETAINER",
      "taxCode": "0102030405",
      "newCompanyName": "Công ty TNHH Giải pháp STAX",
      "teamAssignments": [
        {"employeeId": 10, "role": "LEAD_DIRECTOR"}
      ]
    }
    ```
*   **Ví dụ (curl):**
    ```bash
    curl -X POST http://api.stax.com/crm/leads/1/won \
      -H "Authorization: Bearer <Access_Token>" \
      -H "Content-Type: application/json" \
      -d '{
        "contractNumber": "CN-2024-007",
        "feeAmount": 15000000,
        "serviceType": "ONE_OFF"
      }'
    ```

---

## 3. MÔ ĐUN: KẾ TOÁN (ACCOUNTING)
**Prefix:** `/accounting/finotes`

### 📄 Tạo phiếu Thu/Chi (Create Finote)
*   **Endpoint:** `POST /accounting/finotes`
*   **Mô tả:** Ghi nhận một phiếu đề nghị thu tiền khách hàng hoặc chi tiền nội bộ.
*   **Quyền:** `finote:create`
*   **Body (JSON):**
    ```json
    {
      "type": "INCOME",
      "totalAmount": 5000000,
      "description": "Thu tiền dịch vụ tháng 04",
      "organizationId": 5,
      "items": [
        {"description": "Phí tư vấn", "amount": 5000000}
      ]
    }
    ```
*   **Ví dụ (curl):**
    ```bash
    curl -X POST http://api.stax.com/accounting/finotes \
      -H "Authorization: Bearer <Access_Token>" \
      -H "Content-Type: application/json" \
      -d '{
        "type": "INCOME",
        "totalAmount": 2000000,
        "description": "Cọc phí",
        "organizationId": 12
      }'
    ```

---

## 4. MÔ ĐUN: QUẢN TRỊ QUYỀN (RBAC)
**Prefix:** `/rbac/data`

### 📤 Export dữ liệu RBAC
*   **Endpoint:** `GET /rbac/data/export`
*   **Mô tả:** Xuất toàn bộ ma trận phân quyền của hệ thống ra file CSV.
*   **Ví dụ (curl):**
    ```bash
    curl -X GET http://api.stax.com/rbac/data/export \
      -H "Authorization: Bearer <Access_Token>" \
      --output permissions.csv
    ```

### 📥 Import dữ liệu RBAC
*   **Endpoint:** `POST /rbac/data/import`
*   **Mô tả:** Cập nhật hàng loạt quyền và gán vai trò nhân viên từ file CSV.
*   **Body:** `multipart/form-data` (field `file`).
*   **Ví dụ (curl):**
    ```bash
    curl -X POST http://api.stax.com/rbac/data/import \
      -H "Authorization: Bearer <Access_Token>" \
      -F "file=@rbac_rules.csv"
    ```

---

## 5. MÔ ĐUN: GIÁM SÁT (LOGGING)
**Prefix:** `/logging`

### 📈 Activity Feed (Dòng hoạt động)
*   **Endpoint:** `GET /logging/activity-feed`
*   **Mô tả:** Truy xuất lịch sử thay đổi của một tài nguyên bất kỳ (Lead, Organization, v.v.).
*   **Query Params:**
    *   `resource`: Tên bảng (VD: `leads`)
    *   `resourceId`: ID của bản ghi.
*   **Ví dụ:** `GET /logging/activity-feed?resource=leads&resourceId=1`
*   **Hiển thị (Delta Logic):**
    ```json
    {
      "action": "LEAD.STAGE_CHANGED",
      "before": {"stage": "NEW"},
      "after": {"stage": "WON"},
      "timestamp": "2026-04-26T22:15:00Z"
    }
    ```
*   **Ví dụ (curl):**
    ```bash
    curl -X GET "http://api.stax.com/logging/activity-feed?resource=leads&resourceId=1" \
      -H "Authorization: Bearer <Access_Token>"
    ```

---

## 💡 CÁCH SỬ DỤNG CHUNG (GUIDELINES)
1.  **Xác thực:** Mọi API (trừ `/auth/login`, `/auth/register`) đều yêu cầu Bearer Token trong header.
2.  **Định dạng:** Toàn bộ dữ liệu gửi và nhận đều là `application/json`.
3.  **Mã lỗi:**
    *   `401 Unauthorized`: Token hết hạn hoặc không hợp lệ.
    *   `403 Forbidden`: Tài khoản không đủ quyền (Permission) để thực hiện hành động.
    *   `400 Bad Request`: Dữ liệu đầu vào sai định dạng hoặc vi phạm ràng buộc nghiệp vụ.

---
*Tài liệu được cập nhật ngày 26/04/2026 - STAX Architecture Doc.*
