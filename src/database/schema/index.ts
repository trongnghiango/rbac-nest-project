/**
 * src/database/schema/index.ts
 *
 * File gom export toàn bộ schema — Drizzle dùng file này để:
 * 1. Sinh migration (drizzle-kit generate)
 * 2. Cho phép query relational (db.query.xxx)
 *
 * Thứ tự import quan trọng — import bảng cha trước bảng con
 * để tránh circular dependency khi Drizzle resolve relations.
 */

// ─── CORE ────────────────────────────────────────────────────────────────────
export * from './core/users.schema';
export * from './core/sessions.schema';       // FIX: thêm index token + refresh_token

// ─── RBAC ────────────────────────────────────────────────────────────────────
export * from './rbac/rbac.schema';           // FIX: đổi tên cột sang snake_case

// ─── SYSTEM ──────────────────────────────────────────────────────────────────
export * from './system/notifications.schema';
export * from './system/attachments.schema';  // NEW: File đính kèm dùng chung (Polymorphic)
export * from './system/sequences.schema';
export * from './system/audit-logs.schema';   // NEW: Audit Log toàn hệ thống

// ─── HRM ─────────────────────────────────────────────────────────────────────
export * from './hrm/org-structure.schema';   // locations, grades, orgUnits, positions
export * from './hrm/employees.schema';       // employees, performanceReviews

// ─── CRM ─────────────────────────────────────────────────────────────────────
// Import đúng thứ tự: organizations trước (bảng cha), leads/contracts/quotes sau (bảng con)
export * from './crm/organizations.schema';   // FIX: userId nullable
export * from './crm/leads.schema';           // NEW: Pipeline bán hàng
export * from './crm/contracts.schema';       // NEW: Hợp đồng khách hàng
export * from './crm/quotes.schema';          // NEW: Báo giá + Quote Items
export * from './crm/contacts.schema'; // <-- NEW
export * from './crm/service-assignments.schema'; // <-- NEW
export * from './crm/interaction-notes.schema'; // <-- NEW

// ─── ACCOUNTING ──────────────────────────────────────────────────────────────
export * from './accounting/finotes.schema';  // NEW: Phiếu ĐNTT + Attachments