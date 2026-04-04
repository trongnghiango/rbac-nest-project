Chào bạn, đây là một ý tưởng rất tuyệt vời! Khi hệ thống lớn lên (Enterprise), việc nhồi nhét tất cả vào một sơ đồ duy nhất sẽ tạo ra một "mạng nhện" chằng chịt, rất khó để đọc và giải thích cho khách hàng.

Để mỗi sơ đồ khi copy vào [dbdiagram.io](https://dbdiagram.io/d) có thể chạy độc lập mà không bị lỗi, tôi sẽ **tạo thêm một bảng `users` (rút gọn)** vào các module RBAC, HRM, CRM. Bảng `users` này đóng vai trò là "mỏ neo" để bạn thấy các module khác kết nối với Core Identity như thế nào.

Dưới đây là mã DBML đã được chia làm 4 phần độc lập. Bạn có thể tạo 4 tab (hoặc 4 file) trên dbdiagram.io để lưu lại nhé:

---

### PHẦN 1: MODULE CORE (Tài khoản, Phiên đăng nhập & Hệ thống)
*Sơ đồ này tập trung vào cốt lõi định danh người dùng, lưu trữ metadata, quản lý phiên đăng nhập và thông báo hệ thống.*

```dbml
// ==========================================
// 1. MODULE CORE (IDENTITY, SESSIONS & SYSTEM)
// ==========================================

Table users {
  id bigint [pk, increment]
  username text [not null, unique]
  email text [unique]
  hashedPassword text
  telegramId varchar(50) [unique]
  isActive boolean [default: true]
  deletedAt timestamp
  createdAt timestamp [default: `now()`]
  updatedAt timestamp [default: `now()`]
}

Table user_metadata {
  userId bigint [pk, note: 'PK and FK to users.id']
  fullName text
  avatarUrl text
  bio text
  phoneNumber text
  settings jsonb [default: '{"theme":"light","lang":"vi"}']
  updatedAt timestamp [default: `now()`]
}

Table sessions {
  id uuid [pk, default: `random_uuid()`]
  userId bigint [not null]
  token text [not null]
  refreshToken text [not null]
  expiresAt timestamp [not null]
  ipAddress text
  userAgent text
  createdAt timestamp [not null, default: `now()`]
}

Table notifications {
  id integer [pk, increment]
  userId integer [not null]
  type text [not null, note: 'EMAIL, SMS, PUSH']
  subject text [not null]
  content text [not null]
  status text [not null, note: 'PENDING, SENT, FAILED']
  sentAt timestamp
  createdAt timestamp [default: `now()`]
}

// Relationships
Ref: users.id - user_metadata.userId // 1-to-1
Ref: users.id < sessions.userId // 1-to-N
Ref: users.id < notifications.userId // 1-to-N

TableGroup Core {
  users
  user_metadata
  sessions
  notifications
}
```

---

### PHẦN 2: MODULE RBAC (Phân quyền động)
*Sơ đồ này tập trung vào ma trận phân quyền: User có Role gì, Role có Permission gì.*

```dbml
// ==========================================
// 2. MODULE RBAC (PHÂN QUYỀN ĐỘNG)
// ==========================================

// Bảng Users rút gọn để làm mỏ neo kết nối
Table users {
  id bigint [pk, increment, note: 'Core Identity']
  username text
}

Table roles {
  id integer [pk, increment]
  name text [not null, unique]
  description text
  isActive boolean [default: true]
  isSystem boolean [default: false]
  createdAt timestamp [default: `now()`]
  updatedAt timestamp [default: `now()`]
}

Table permissions {
  id integer [pk, increment]
  name text [not null, unique]
  description text
  resourceType text
  action text
  attributes text [default: '*']
  isActive boolean [default: true]
  createdAt timestamp [default: `now()`]
}

Table user_roles {
  userId bigint [not null]
  roleId integer [not null]
  assignedBy bigint
  expiresAt timestamp
  assignedAt timestamp [default: `now()`]
  
  indexes {
    (userId, roleId) [pk]
  }
}

Table role_permissions {
  roleId integer [not null]
  permissionId integer [not null]
  
  indexes {
    (roleId, permissionId) [pk]
  }
}

// Relationships
Ref: users.id < user_roles.userId
Ref: roles.id < user_roles.roleId
Ref: roles.id < role_permissions.roleId
Ref: permissions.id < role_permissions.permissionId

TableGroup RBAC {
  roles
  permissions
  user_roles
  role_permissions
}
```

---

### PHẦN 3: MODULE HRM (Nhân sự & Tổ chức)
*Đây là module phức tạp nhất, mô tả cấu trúc cây phòng ban (Org Chart), hệ thống chức danh, ngạch bậc lương và hồ sơ nhân sự.*

```dbml
// ==========================================
// 3. MODULE HRM (NHÂN SỰ & TỔ CHỨC)
// ==========================================

// Bảng Users rút gọn để kết nối Tài khoản -> Nhân sự
Table users {
  id bigint [pk, increment, note: 'Core Identity']
}

Table locations {
  id integer [pk, increment]
  code varchar(50) [not null, unique]
  name varchar(255) [not null]
  isActive boolean [default: true]
}

Table grades {
  id integer [pk, increment]
  levelNumber integer [not null, unique, note: '1, 2, 3... 10']
  code varchar(50) [not null, unique]
  name varchar(255) [not null]
}

Table salary_scales {
  id integer [pk, increment]
  gradeId integer [not null]
  baseSalary numeric(15,2)
  coefficient numeric(5,2)
  effectiveDate timestamp
}

Table job_titles {
  id integer [pk, increment]
  name varchar(255) [not null, unique, note: 'Trưởng phòng, Chuyên viên...']
}

Table org_units {
  id integer [pk, increment]
  parentId integer
  path varchar(255) [note: 'Materialized path (e.g., /1/3/4/)']
  type varchar(50) [not null, note: 'COMPANY, DEPARTMENT, TEAM']
  code varchar(50) [not null, unique]
  name varchar(255) [not null]
  isActive boolean [default: true]
}

Table positions {
  id integer [pk, increment]
  code varchar(50) [not null, unique, note: 'POS-IT-06']
  name varchar(255) [not null, note: 'CV-IT']
  orgUnitId integer [not null]
  jobTitleId integer [not null]
  gradeId integer [not null]
  headcountLimit integer [default: 1]
  isActive boolean [default: true]
}

Table employees {
  id integer [pk, increment]
  userId bigint [unique, note: '1 User maps to 1 Employee']
  employeeCode text [not null, unique]
  fullName text [not null]
  dateOfBirth date
  locationId integer
  positionId integer
  managerId integer
  joinDate date
}

Table performance_reviews {
  id integer [pk, increment]
  employeeId integer [not null]
  reviewerId integer
  reviewPeriod text [not null]
  score numeric(5,2)
  proposedPositionId integer
  status text [default: 'PENDING']
}

// Relationships
Ref: org_units.id < org_units.parentId // Self-referencing (Tree)
Ref: grades.id < salary_scales.gradeId
Ref: org_units.id < positions.orgUnitId
Ref: job_titles.id < positions.jobTitleId
Ref: grades.id < positions.gradeId
Ref: users.id - employees.userId // 1-to-1 (User Profile)
Ref: locations.id < employees.locationId
Ref: positions.id < employees.positionId
Ref: employees.id < employees.managerId // Self-referencing (Manager)
Ref: employees.id < performance_reviews.employeeId
Ref: employees.id < performance_reviews.reviewerId
Ref: positions.id < performance_reviews.proposedPositionId

TableGroup HRM {
  employees
  org_units
  positions
  job_titles
  grades
  salary_scales
  locations
  performance_reviews
}
```

---

### PHẦN 4: MODULE CRM (Tổ chức đối tác / Khách hàng)
*Sơ đồ này quản lý thông tin các tổ chức/khách hàng B2B, kết nối với tài khoản để họ có thể đăng nhập vào Client Portal.*

```dbml
// ==========================================
// 4. MODULE CRM (KHÁCH HÀNG / B2B)
// ==========================================

// Bảng Users rút gọn để kết nối Tài khoản -> Khách hàng
Table users {
  id bigint [pk, increment, note: 'Core Identity']
  email text [unique]
}

Table organizations {
  id integer [pk, increment]
  userId bigint [not null, unique, note: 'For CRM Portal Login']
  companyName text [not null]
  taxCode text [unique]
  industry text
  website text
  contactPerson text
  contactPhone text
  status text [default: 'LEAD']
  createdAt timestamp [default: `now()`]
}

// Relationships
Ref: users.id - organizations.userId // 1-to-1 (Client Portal)

TableGroup CRM {
  organizations
}
```

---

### 💡 Lời khuyên khi present với khách hàng (STAX):
1. Bạn hãy xuất 4 sơ đồ này thành **4 ảnh PDF/PNG riêng biệt**.
2. Đặt tên chúng thành các slide tương ứng: `1. Core Architecture`, `2. Security & RBAC`, `3. HRM Enterprise Structure`, `4. CRM Portal`.
3. Giải thích với họ: *"Để đảm bảo hệ thống có thể scale (mở rộng) dễ dàng, team đã thiết kế theo kiến trúc Modular. Bất cứ khi nào STAX muốn thêm tính năng (ví dụ: Module Kế toán, Module Kho), chúng ta chỉ việc cắm (plug-in) vào Module Core mà không sợ làm sập các module đang chạy."* Khách hàng sẽ đánh giá rất cao tư duy hệ thống này của bạn!