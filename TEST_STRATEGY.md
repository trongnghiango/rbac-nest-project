# 🧪 CHIẾN LƯỢC KIỂM THỬ (TEST STRATEGY)

Việc viết test không phải là "việc thêm", mà là một phần của quy trình phát triển. Dưới đây là chiến lược và quy tắc test cho dự án theo mô hình Hexagonal.

## 1. TẠI SAO CẦN VIẾT TEST?
1.  **Dẻo dai khi Refactor:** Khi bạn đổi logic bên trong, nếu test vẫn Pass, bạn yên tâm là không làm hỏng tính năng cũ.
2.  **Tài liệu sống:** Đọc code test là cách nhanh nhất để hiểu một hàm nhận vào cái gì và trả ra cái gì.
3.  **Bắt lỗi sớm:** Phát hiện lỗi ngay lúc vừa code xong thay vì đợi đến khi Deploy lên Staging.

---

## 2. KIẾN TRÚC TEST (THE PYRAMID)

Chúng ta áp dụng mô hình Kim tự tháp để tối ưu chi phí và tốc độ:

### 🟢 Cấp 1: Unit Test (80% - Ưu tiên số 1)
*   **Đối tượng:** Domain Entity, Application Service, Utils.
*   **Đặc điểm:** Cực nhanh (chạy hàng trăm test trong vài giây). **KHÔNG** kết nối Database, **KHÔNG** gọi API ngoài. 
*   **Kỹ thuật:** Sử dụng **Mocking** để giả lập các Repository/Port.

### 🟡 Cấp 2: Integration Test (15%)
*   **Đối tượng:** Repository (Drizzle), Adapter (Redis, Email Service).
*   **Đặc điểm:** Kiểm tra xem code của chúng ta có nói chuyện đúng với Database không. Cần có Database thật (thường dùng Docker/In-memory DB).

### 🔴 Cấp 3: E2E Test (5% - Hạn chế)
*   **Đối tượng:** Toàn bộ API Route (từ Controller -> DB).
*   **Đặc điểm:** Chạy chậm, dễ bị "Flaky" (lúc pass lúc fail do môi trường). Chỉ dùng để test các luồng quan trọng nhất (Happy Path).

---

## 3. QUY TẮC VÀNG KHI VIẾT TEST (THE LAWS)

1.  **Quy tắc AAA (Arrange - Act - Assert):**
    *   **Arrange:** Chuẩn bị dữ liệu mẫu, mock các service liên quan.
    *   **Act:** Thực thi hàm cần test.
    *   **Assert:** Kiểm tra kết quả trả về có đúng kỳ vọng không.
2.  **Tính Độc lập:** Test A không được phụ thuộc vào kết quả của Test B. Mỗi test phải tự khởi tạo và dọn dẹp dữ liệu của mình.
3.  **Dữ liệu thực tế:** Không nên dùng dữ liệu "abc", "123". Hãy dùng thư viện như `@faker-js/faker` để tạo email, tên tuổi trông như thật.
4.  **Cấm Logic trong Test:** Đừng viết `if-else` trong file test. Test phải cực kỳ đơn giản và dễ đọc.

---

## 4. CHIẾN THUẬT DATA-DRIVEN TESTING (Mọi đầu vào)

Để cover mọi tình huống "hiểm hóc", chúng ta sử dụng kỹ thuật truyền danh sách input (từ file JSON/CSV).

**Ví dụ Pattern trong Jest:**
```typescript
describe('UserAccountService.provisionAccount()', () => {
  it.each([
    { username: 'valid', email: 'test@stax.vn', expected: 'SUCCESS' },
    { username: '', email: 'test@stax.vn', expected: 'FAIL_EMPTY_USERNAME' },
    { username: 'admin', email: 'wrong-email', expected: 'FAIL_INVALID_EMAIL' },
    { username: 'duplicate_user', email: 'new@stax.vn', expected: 'FAIL_DUPLICATE' },
  ])('Case: $expected', async (props) => {
    // Thực thi test với data tương ứng
  });
});
```

---

## 5. LỘ TRÌNH TRIỂN KHAI CHO TEAM

Nếu bạn chưa từng viết test, hãy bắt đầu theo thứ tự này:
1.  **Viết test cho Domain Entity:** Đây là nơi dễ nhất vì không có dependency (ví dụ: `User.changePassword()`).
2.  **Viết test cho Application Service:** Mock các Repository Port.
3.  **Viết test cho Utils:** Các hàm xử lý chuỗi, ngày tháng, tính toán.

> **💡 Lời khuyên:** Đừng cố đạt 100% Coverage (độ bao phủ code). Hãy tập trung test các **Nghiệp vụ quan trọng nhất (Business Core)** trước. Thà có 10 test chất lượng cho luồng Bán hàng còn hơn có 100 test vô thưởng vô phạt cho các hàm CRUD đơn giản.
