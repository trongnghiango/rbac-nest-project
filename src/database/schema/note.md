

### 📂 Cấu trúc thư mục Database Schema
```
src/database/schema/
├── index.ts                           # File gom (Export all) để cấu hình Drizzle
├── core/
│   ├── users.schema.ts                # Định danh, Đăng nhập (Identity)
│   └── sessions.schema.ts             # Phiên làm việc (Tokens)
├── rbac/
│   └── rbac.schema.ts                 # Roles, Permissions, Phân quyền
├── hrm/
│   ├── org-structure.schema.ts        # Sơ đồ tổ chức, chức danh, cấp bậc
│   └── employees.schema.ts            # Hồ sơ Nhân viên (Profile)
├── crm/
│   └── organizations.schema.ts        # Hồ sơ Doanh nghiệp/Đối tác B2B (Profile)
└── system/
    └── notifications.schema.ts        # Thông báo hệ thống
```

> Vì sao lại tổ chức cấu trúc thư mục `schema` như cấu trúc trên? Rõ ràng theo modules nên khi tách microservices sẽ dễ dàng theo modules và thấy rõ schema của module nào cần tách. Đồng thời cũng phù hợp vói cách tổ chức của Drizzle ORM.
### 