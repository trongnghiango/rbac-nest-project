
### MÃ DBML ĐỂ COPY VÀO DBDIAGRAM.IO:

```dbml
// ==========================================
// HỆ THỐNG ERP/HRM TỔNG THỂ (STAX)
// ==========================================

// ------------------------------------------
// 1. MODULE CORE (IDENTITY & SESSIONS)
// ------------------------------------------
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

// ------------------------------------------
// 2. MODULE RBAC (PHÂN QUYỀN ĐỘNG)
// ------------------------------------------
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

// ------------------------------------------
// 3. MODULE HRM (NHÂN SỰ & TỔ CHỨC)
// ------------------------------------------
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
  deletedAt timestamp
  createdAt timestamp [default: `now()`]
  updatedAt timestamp [default: `now()`]
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
  phoneNumber text
  avatarUrl text
  locationId integer
  positionId integer
  managerId integer
  joinDate date
  createdAt timestamp [default: `now()`]
  updatedAt timestamp [default: `now()`]
}

Table performance_reviews {
  id integer [pk, increment]
  employeeId integer [not null]
  reviewerId integer
  reviewPeriod text [not null]
  score numeric(5,2)
  comments text
  proposedPositionId integer
  status text [default: 'PENDING']
  createdAt timestamp [default: `now()`]
}

// ------------------------------------------
// 4. MODULE CRM (KHÁCH HÀNG / B2B)
// ------------------------------------------
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

// ------------------------------------------
// 5. MODULE SYSTEM (HỆ THỐNG)
// ------------------------------------------
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


// ==========================================
// RELATIONSHIPS (KHÓA NGOẠI - FK)
// ==========================================

// Core & Sessions
Ref: users.id - user_metadata.userId // 1-to-1
Ref: users.id < sessions.userId // 1-to-N

// RBAC
Ref: users.id < user_roles.userId
Ref: roles.id < user_roles.roleId
Ref: roles.id < role_permissions.roleId
Ref: permissions.id < role_permissions.permissionId

// HRM - Org Structure
Ref: org_units.id < org_units.parentId // Self-referencing (Tree)
Ref: grades.id < salary_scales.gradeId
Ref: org_units.id < positions.orgUnitId
Ref: job_titles.id < positions.jobTitleId
Ref: grades.id < positions.gradeId

// HRM - Employees
Ref: users.id - employees.userId // 1-to-1 (User Profile)
Ref: locations.id < employees.locationId
Ref: positions.id < employees.positionId
Ref: employees.id < employees.managerId // Self-referencing (Manager)

// HRM - Performance
Ref: employees.id < performance_reviews.employeeId
Ref: employees.id < performance_reviews.reviewerId
Ref: positions.id < performance_reviews.proposedPositionId

// CRM
Ref: users.id - organizations.userId // 1-to-1 (Client Portal)

// System
Ref: users.id < notifications.userId

// ==========================================
// TẠO NHÓM (TABLE GROUPS) CHO GIAO DIỆN ĐẸP
// ==========================================
TableGroup Core {
  users
  user_metadata
  sessions
}

TableGroup RBAC {
  roles
  permissions
  user_roles
  role_permissions
}

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

TableGroup CRM {
  organizations
}

TableGroup System {
  notifications
}
```

### Cách sử dụng DBML này:
1. Mở trang [https://dbdiagram.io/](https://dbdiagram.io/d) (Miễn phí, không cần đăng nhập).
2. Xóa toàn bộ code có sẵn bên trái.
3. Paste đoạn code trên vào.
4. Ở khung bên phải, bạn sẽ thấy một sơ đồ cực kỳ hoành tráng được phân theo từng vùng màu sắc (`TableGroup`):
   * **Core** (Tài khoản, phiên bản)
   * **RBAC** (Phân quyền)
   * **HRM** (Phòng ban, Chức danh, Nhân sự, Đánh giá)
   * **CRM** (Tổ chức đối tác)
5. Bạn có thể kéo thả các bảng cho ngay ngắn, sau đó ấn **Export -> Export to PDF / PNG** để đính kèm vào Hợp đồng hoặc Proposal gửi cho STAX.

*(Khách hàng nhìn thấy sơ đồ Database quy mô và bài bản thế này, họ sẽ hiểu ngay "Kiến trúc Enterprise" mà bạn đề xuất không phải là lời nói suông!)*