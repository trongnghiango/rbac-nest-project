# Implementation Plan: STAX Universal Legacy Data Migration

This plan outlines the systematic migration of legacy business data (currently managed in Excel) into the hardened STAX CRM/Accounting system. The goal is to transform flat, redundant Excel rows into a normalized, relational, and type-safe database state while preserving 100% of historical context.

## User Review Required

> [!IMPORTANT]
> **Key Identifier Consistency**: The migration relies on **Phone Numbers** (for Contacts) and **Tax Codes (MST)** or **Company Names** (for Organizations) to link records across sheets. Please ensure these columns are as clean as possible in the Excel source.

> [!WARNING]
> **Greedy Columns Handling**: Since the Excel sheets contain more info than our current schema (e.g., "Nick name", "TG làm việc"), these "greedy" columns will be stored in a `metadata` JSONB field in their respective entities.

## Proposed Changes

### 1. Migration Infrastructure [NEW]

We will create a specialized migration engine to handle the messy nature of Excel data.

#### [NEW] [legacy-migration.script.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/test/application/scripts/legacy-migration.script.ts)
- A standalone script (invokable via CLI or a temp endpoint) that orchestrates the multi-stage migration.
- **Deduplication Buffer**: In-memory Maps to track created IDs to prevent duplicate Organizations/Contacts when they appear in multiple rows/sheets.
- **Enum Mappers**: Converters for Vietnamese status strings (e.g., "Đã chốt" -> `LeadStage.WON`).

---

### 2. Migration Stages (The Pipeline)

The migration will follow a strict order to maintain relational integrity:

#### Stage 1: Employees (The Actors)
- **Source**: `Bảng nhân viên`.
- **Action**: Create `User` and `Employee` records.
- **Purpose**: Provides valid IDs for "AssignedTo", "RequestedBy", and "Service Assignments".

#### Stage 2: Organizations & Contacts (The Entities)
- **Source**: `Bảng Excel Client`.
- **Action**: 
    1. Create `Organization`.
    2. Create two `Contact` records (Legal Rep and Operational Contact).
- **Deduplication**: Match by MST first, then Phone.

#### Stage 3: Contracts (The Revenue Base)
- **Source**: `Bảng Excel Client` (Contract-related columns).
- **Action**: Create `Contract` records linked to the new Orgs.
- **Logics**: Map "Tình trạng HĐ" to `ContractStatus` enum.

#### Stage 4: Leads (The Growth History)
- **Source**: `Bảng Lead`.
- **Action**: Create `Lead` records.
- **Linking**: Match to existing Orgs via Phone. If no Org matches, use `LeadIntakeService` to create a placeholder Org.

#### Stage 5: Finotes & Accounting (The Financial State)
- **Source**: `Bảng Excel Finote`.
- **Action**: Create `Finote` and `FinoteItem` records.
- **Linking**: Match to Orgs via MST or Name.
- **Reconciliation**: If "Số tiền thanh toán" matches "Tổng phí", set status to `PAID`.

---

### 3. Service Assignments (The Responsibility Matrix)
- **Source**: `Giám đốc`, `Leader`, `Trợ lý` columns from both Client and Finote sheets.
- **Action**: Populate the `ServiceAssignments` table to reflect who is responsible for each client.

---

## Technical Mapping Details

| Entity | Primary Key Mapping | Metadata (JSONB) Storage |
| :--- | :--- | :--- |
| **Employee** | `Mã NV` | `Start`, `Now`, `TG làm việc` |
| **Organization** | `Tên công ty`, `MST` | `ShortName`, `Nick name` |
| **Contract** | `Số hợp đồng` | `THỜI HẠN TẠM NGƯNG` |
| **Lead** | (Auto ID) | `Báo giá đính kèm`, `Nick name` |
| **Finote** | `SỐ FN` | `SỐ HÓA ĐƠN`, `VAT` |

---

## Open Questions

- **Missing MSTs**: If a client in the `Finote` sheet doesn't have an `MST`, should we attempt to match by `Company Name` (Fuzzy matching), or should it fail?
- **Legacy IDs**: Do you want us to store the `STT` or a specific `Legacy ID` in a field so you can cross-reference with the old Excel files later? (Highly Recommended).

## Verification Plan

### Automated Tests
- Create a "Mini Migration" test suite that processes 5 sample rows of each type and asserts the correct relational linkage in the DB.
- Run `npx tsc` to ensure no type errors in the migration logic.

### Manual Verification
- After migration, we will pick 10 random clients and verify their `Activity Timeline` to ensure we can see their Lead history, Contract status, and Balance correctly.
