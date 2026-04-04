## File: src/database/schema/system/notifications.schema.ts
```
import {
  pgTable,
  serial,
  text,
  timestamp,
  integer,
  boolean,
} from 'drizzle-orm/pg-core';

export const notifications = pgTable('notifications', {
  id: serial('id').primaryKey(),
  userId: integer('userId').notNull(), // Liên kết lỏng với bảng Users
  type: text('type').notNull(), // EMAIL, SMS
  subject: text('subject').notNull(),
  content: text('content').notNull(),
  status: text('status').notNull(), // PENDING, SENT
  sentAt: timestamp('sentAt'),
  createdAt: timestamp('createdAt').defaultNow(),
});

```

## File: src/database/schema/hrm/employees.schema.ts
```
import { pgTable, serial, text, integer, date, timestamp, bigint, numeric } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';
import { locations, positions } from './org-structure.schema';

// 1. Hồ sơ Nhân viên
export const employees = pgTable('employees', {
    id: serial('id').primaryKey(),
    userId: bigint('user_id', { mode: 'number' })
        .unique() // Vẫn giữ unique để 1 User chỉ map 1 Employee
        .references(() => users.id, { onDelete: 'set null' }), // Đổi cascade thành set null để khi xóa User, hồ sơ NV vẫn còn

    employeeCode: text('employee_code').notNull().unique(), // VD: 001, 007
    fullName: text('full_name').notNull(),
    dateOfBirth: date('date_of_birth'),
    phoneNumber: text('phone_number'),
    avatarUrl: text('avatar_url'),

    // 👉 THAY ĐỔI LỚN: NV liên kết trực tiếp với Vị trí (Position) và Địa điểm (Location)
    locationId: integer('location_id').references(() => locations.id), // Nơi làm việc (HCM)
    positionId: integer('position_id').references(() => positions.id), // Vị trí công việc (Bao hàm cả Phòng, Chức danh, Bậc)

    managerId: integer('manager_id'), // Người quản lý trực tiếp

    joinDate: date('join_date'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
});

// 2. 🔥 BẢNG MỚI: KỲ ĐÁNH GIÁ (PERFORMANCE REVIEWS - Lộ trình thăng tiến)
export const performanceReviews = pgTable('performance_reviews', {
    id: serial('id').primaryKey(),
    employeeId: integer('employee_id').notNull().references(() => employees.id, { onDelete: 'cascade' }),
    reviewerId: integer('reviewer_id').references(() => employees.id), // Người đánh giá (Manager)

    reviewPeriod: text('review_period').notNull(), // VD: "Q1-2026"
    score: numeric('score', { precision: 5, scale: 2 }), // Điểm đánh giá
    comments: text('comments'),

    // Đề xuất sau đánh giá
    proposedPositionId: integer('proposed_position_id').references(() => positions.id), // Đề xuất lên vị trí/bậc mới
    status: text('status').default('PENDING'), // PENDING, APPROVED, REJECTED

    createdAt: timestamp('created_at').defaultNow(),
});

// --- RELATIONS ---
export const employeesRelations = relations(employees, ({ one, many }) => ({
    user: one(users, { fields: [employees.userId], references: [users.id] }),
    location: one(locations, { fields: [employees.locationId], references: [locations.id] }),

    // Liên kết chặt chẽ với Ma trận Vị trí
    position: one(positions, { fields: [employees.positionId], references: [positions.id] }),

    manager: one(employees, { fields: [employees.managerId], references: [employees.id], relationName: 'managerRelation' }),
    subordinates: many(employees, { relationName: 'managerRelation' }),
    reviews: many(performanceReviews, { relationName: 'employeeReviews' }),
}));

export const performanceReviewsRelations = relations(performanceReviews, ({ one }) => ({
    employee: one(employees, { fields: [performanceReviews.employeeId], references: [employees.id], relationName: 'employeeReviews' }),
    reviewer: one(employees, { fields: [performanceReviews.reviewerId], references: [employees.id] }),
    proposedPosition: one(positions, { fields: [performanceReviews.proposedPositionId], references: [positions.id] }),
}));


```

## File: src/database/schema/hrm/org-structure.schema.ts
```
import { pgTable, serial, varchar, integer, boolean, timestamp, numeric, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { employees } from './employees.schema';

// 1. Địa điểm làm việc (Chi nhánh, Tòa nhà)
export const locations = pgTable('locations', {
    id: serial('id').primaryKey(),
    code: varchar('code', { length: 50 }).unique().notNull(), // VD: HCM, HN
    name: varchar('name', { length: 255 }).notNull(),
    isActive: boolean('is_active').default(true),
});

// 2. Cấp bậc lương / Rank (Từ Bậc 1 -> Bậc 10 như Hình 2)
export const grades = pgTable('grades', {
    id: serial('id').primaryKey(),
    levelNumber: integer('level_number').notNull().unique(), // 1, 2... 10
    code: varchar('code', { length: 50 }).unique().notNull(), // BAC_1, BAC_10
    name: varchar('name', { length: 255 }).notNull(),
});

// 3. Thang bảng lương (Salary Scales) - Link với Bậc
export const salaryScales = pgTable('salary_scales', {
    id: serial('id').primaryKey(),
    gradeId: integer('grade_id').notNull().references(() => grades.id, { onDelete: 'cascade' }),
    baseSalary: numeric('base_salary', { precision: 15, scale: 2 }), // Lương cơ bản
    coefficient: numeric('coefficient', { precision: 5, scale: 2 }), // Hệ số lương (VD: 2.34)
    effectiveDate: timestamp('effective_date'), // Ngày áp dụng
});

// 4. Chức danh công việc chung (Generic Job Titles)
export const jobTitles = pgTable('job_titles', {
    id: serial('id').primaryKey(),
    name: varchar('name', { length: 255 }).notNull().unique(), // Trưởng phòng, Chuyên viên, Trợ lý...
});

// 5. Cơ cấu tổ chức (Sơ đồ cây: Công ty -> Khối -> Phòng -> Nhóm)
export const orgUnits = pgTable('org_units', {
    id: serial('id').primaryKey(),
    parentId: integer('parent_id'),
    path: varchar('path', { length: 255 }), //Trường path lưu cấu trúc cây (VD: /1/3/4/)
    type: varchar('type', { length: 50 }).notNull(), // COMPANY, BOD, DEPARTMENT, TEAM
    code: varchar('code', { length: 50 }).unique().notNull(),
    name: varchar('name', { length: 255 }).notNull(),
    isActive: boolean('is_active').default(true),
    deletedAt: timestamp('deleted_at'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
}, (table) => ({
    // 👉 Đánh Index B-Tree cho trường path để tăng tốc query LIKE
    pathIdx: index('idx_org_units_path').on(table.path),
}));

// 6. 🔥 BẢNG MỚI: VỊ TRÍ ĐỊNH BIÊN (POSITIONS - MA TRẬN CHỨC DANH)
// Đại diện cho các ô màu vàng/xanh trong Hình 3
export const positions = pgTable('positions', {
    id: serial('id').primaryKey(),
    code: varchar('code', { length: 50 }).unique().notNull(), // VD: POS-IT-06
    name: varchar('name', { length: 255 }).notNull(), // VD: "CV-IT" hoặc "Chuyên viên B2"

    orgUnitId: integer('org_unit_id').notNull().references(() => orgUnits.id), // Thuộc phòng nào
    jobTitleId: integer('job_title_id').notNull().references(() => jobTitles.id), // Mang chức danh gì
    gradeId: integer('grade_id').notNull().references(() => grades.id), // Ở bậc mấy

    headcountLimit: integer('headcount_limit').default(1), // Định biên nhân sự (Số lượng tối đa cho vị trí này)
    isActive: boolean('is_active').default(true),
});

// --- RELATIONS ---
export const orgUnitsRelations = relations(orgUnits, ({ one, many }) => ({
    parent: one(orgUnits, { fields: [orgUnits.parentId], references: [orgUnits.id] }),
    children: many(orgUnits),
    positions: many(positions), // 1 Phòng ban có nhiều Vị trí
}));

export const gradesRelations = relations(grades, ({ many }) => ({
    salaryScales: many(salaryScales),
    positions: many(positions),
}));

export const positionsRelations = relations(positions, ({ one, many }) => ({
    orgUnit: one(orgUnits, { fields: [positions.orgUnitId], references: [orgUnits.id] }),
    jobTitle: one(jobTitles, { fields: [positions.jobTitleId], references: [jobTitles.id] }),
    grade: one(grades, { fields: [positions.gradeId], references: [grades.id] }),
    employees: many(employees), // 1 Vị trí có thể có nhiều nhân viên (nếu headcount > 1)
}));

```

## File: src/database/schema/crm/organizations.schema.ts
```
import { pgTable, serial, text, timestamp, bigint } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from '../core/users.schema';

export const organizations = pgTable('organizations', {
    id: serial('id').primaryKey(),

    // FK trỏ về Users (One-to-One) để đăng nhập cổng Portal CRM
    userId: bigint('user_id', { mode: 'number' })
        .notNull()
        .unique()
        .references(() => users.id, { onDelete: 'cascade' }),

    companyName: text('company_name').notNull(),
    taxCode: text('tax_code').unique(), // Mã số thuế
    industry: text('industry'), // IT, Y Tế, Sản Xuất...
    website: text('website'),

    contactPerson: text('contact_person'),
    contactPhone: text('contact_phone'),

    status: text('status').default('LEAD'), // LEAD, ACTIVE_CUSTOMER, CHURNED
    createdAt: timestamp('created_at').defaultNow(),
});

// --- RELATIONS ---
export const organizationsRelations = relations(organizations, ({ one }) => ({
    user: one(users, { fields: [organizations.userId], references: [users.id] }),
}));

```

## File: src/database/schema/rbac/rbac.schema.ts
```
import {
  pgTable,
  serial,
  text,
  boolean,
  timestamp,
  primaryKey,
  bigint,
  integer,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

import { users } from '../core/users.schema';

// --- 1. TABLES DEFINITIONS ---

// Permissions Table
export const permissions = pgTable('permissions', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  resourceType: text('resourceType'),
  action: text('action'),
  attributes: text('attributes').default('*'),
  isActive: boolean('isActive').default(true),
  createdAt: timestamp('createdAt').defaultNow(),
});

// Roles Table
export const roles = pgTable('roles', {
  id: serial('id').primaryKey(),
  name: text('name').notNull().unique(),
  description: text('description'),
  isActive: boolean('isActive').default(true),
  isSystem: boolean('isSystem').default(false),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
});

// User Roles (Pivot Table: Users <-> Roles)
// ✅ Cập nhật bảng nối userRoles: Thêm references cho userId
export const userRoles = pgTable(
  'user_roles',
  {
    userId: bigint('userId', { mode: 'number' })
      .notNull()
      .references(() => users.id), // Link tới bảng users
    roleId: integer('roleId')
      .notNull()
      .references(() => roles.id), // Link tới bảng roles
    assignedBy: bigint('assignedBy', { mode: 'number' }),
    expiresAt: timestamp('expiresAt', { withTimezone: true }),
    assignedAt: timestamp('assignedAt').defaultNow(),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.userId, t.roleId] }),
  }),
);
// export const userRoles = pgTable(
//   'user_roles',
//   {
//     userId: bigint('userId', { mode: 'number' }).notNull(),
//     roleId: integer('roleId') // Lưu ý: DB column name nên để 'role_id' nếu muốn chuẩn snake_case, ở đây giữ nguyên theo code cũ của bạn
//       .notNull()
//       .references(() => roles.id),
//     assignedBy: bigint('assignedBy', { mode: 'number' }),
//     expiresAt: timestamp('expiresAt', { withTimezone: true }),
//     assignedAt: timestamp('assignedAt').defaultNow(),
//   },
//   (t) => ({
//     pk: primaryKey({ columns: [t.userId, t.roleId] }),
//   }),
// );

// Role Permissions (Pivot Table: Roles <-> Permissions)
export const rolePermissions = pgTable(
  'role_permissions',
  {
    roleId: integer('role_id')
      .notNull()
      .references(() => roles.id),
    permissionId: integer('permission_id')
      .notNull()
      .references(() => permissions.id),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.roleId, t.permissionId] }),
  }),
);

// --- 2. RELATIONS DEFINITIONS ---

// Relations cho Permissions
export const permissionsRelations = relations(permissions, ({ many }) => ({
  roles: many(rolePermissions), // Permission có nhiều entry trong bảng nối rolePermissions
}));

// Relations cho Roles
export const rolesRelations = relations(roles, ({ many }) => ({
  permissions: many(rolePermissions), // Role có nhiều entry trong bảng nối rolePermissions
  // Nếu bạn muốn query ngược từ Role ra User, cần relation này (Optional)
  users: many(userRoles),
}));

// Relations cho RolePermissions (Bảng nối)
export const rolePermissionsRelations = relations(
  rolePermissions,
  ({ one }) => ({
    role: one(roles, {
      fields: [rolePermissions.roleId],
      references: [roles.id],
    }),
    permission: one(permissions, {
      fields: [rolePermissions.permissionId],
      references: [permissions.id],
    }),
  }),
);

// Relations cho UserRoles (Bảng nối) - PHẦN BỊ THIẾU GÂY LỖI
// ✅ Cập nhật Relation cho bảng nối: Định nghĩa 2 chiều
export const userRolesRelations = relations(userRoles, ({ one }) => ({
  role: one(roles, {
    fields: [userRoles.roleId],
    references: [roles.id],
  }),
  user: one(users, {
    fields: [userRoles.userId],
    references: [users.id],
  }),
}));

```

## File: src/database/schema/index.ts
```
// src/database/schema/index.ts

// Core
export * from './core/users.schema';
export * from './core/sessions.schema';

// RBAC
export * from './rbac/rbac.schema';

// System
export * from './system/notifications.schema';

// HRM (Nhân sự)
export * from './hrm/org-structure.schema';
export * from './hrm/employees.schema';

// ✅ BỔ SUNG DÒNG NÀY (CRM - Đối tác/Khách hàng)
export * from './crm/organizations.schema';

```

## File: src/database/schema/core/users.schema.ts
```
import { relations } from 'drizzle-orm';
import { pgTable, bigserial, text, boolean, timestamp, varchar, bigint, jsonb } from 'drizzle-orm/pg-core';
import { userRoles } from '../rbac/rbac.schema';
import { employees } from '../hrm/employees.schema';
import { organizations } from '../crm/organizations.schema';

// --- TABLE ---
export const users = pgTable('users', {
  id: bigserial('id', { mode: 'number' }).primaryKey(),
  username: text('username').notNull().unique(),
  email: text('email').unique(),
  hashedPassword: text('hashedPassword'),
  telegramId: varchar('telegram_id', { length: 50 }).unique(), // Dùng cho Chatbot

  isActive: boolean('is_active').default(true),

  deletedAt: timestamp('deleted_at'),

  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});


export const userMetadata = pgTable('user_metadata', {
  userId: bigint('user_id', { mode: 'number' }).primaryKey().references(() => users.id, { onDelete: 'cascade' }),
  fullName: text('full_name'),
  avatarUrl: text('avatar_url'),
  bio: text('bio'),
  phoneNumber: text('phone_number'),
  // Lưu cài đặt UI/UX (Theme, Ngôn ngữ) vào JSONB vì nó không cần query phức tạp
  settings: jsonb('settings').default({ theme: 'light', lang: 'vi' }),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// --- RELATIONS (Nhìn code như nhìn sơ đồ ERD) ---
export const usersRelations = relations(users, ({ one, many }) => ({
  metadata: one(userMetadata, {
    fields: [users.id],
    references: [userMetadata.userId],
  }),

  // 1 User có nhiều Roles
  userRoles: many(userRoles),

  // Quan hệ 1-1: 1 User có thể là 1 Nhân viên (HRM)
  employeeProfile: one(employees, {
    fields: [users.id],
    references: [employees.userId],
  }),

  // Quan hệ 1-1: 1 User có thể là 1 Khách hàng Doanh nghiệp (CRM)
  organizationProfile: one(organizations, {
    fields: [users.id],
    references: [organizations.userId],
  }),
}));

```

## File: src/database/schema/core/sessions.schema.ts
```
import { pgTable, uuid, bigint, text, timestamp, index } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';
import { users } from './users.schema';

export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id').defaultRandom().primaryKey(),
    userId: bigint('user_id', { mode: 'number' }).notNull().references(() => users.id, { onDelete: 'cascade' }),
    token: text('token').notNull(),
    refreshToken: text('refresh_token').notNull(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => ({
    userIdIdx: index('idx_sessions_user_id').on(table.userId),
  }),
);

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, { fields: [sessions.userId], references: [users.id] }),
}));

```

## File: src/database/schema/note.md
```


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
```

