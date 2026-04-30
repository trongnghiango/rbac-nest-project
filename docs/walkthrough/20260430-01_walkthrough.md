# Clean Architecture Fixes Walkthrough

I have addressed the Clean Architecture violations as outlined in the implementation plan. Here is a summary of the changes:

## Changes Made

### 1. Domain Encapsulation (`Finote` Entity)
- **Status & ReviewerId Hidden**: The `status` and `reviewerId` properties are now hidden behind `_status` and `_reviewerId` private fields with appropriate getters.
- **Controlled State Mutation**: Added `approve(reviewerId)` and `reject(reviewerId, reason)` methods natively into the `Finote` entity. These methods contain the business logic required to transition between states (e.g. throwing errors if the status isn't `PENDING`).
- **Refactored Service Implementation**: `FinoteService` no longer modifies `finote.status` or `finote.reviewerId` directly but delegates state changes to the `finote` domain model.

### 2. Simplified Mapping Logic (`EmployeeMapper`)
- Removed redundant ternary conditionals and checks such as `raw.userId ? Number(raw.userId) : (raw.userId ? Number(raw.userId) : undefined)` in favor of cleaner standard property mapping.

### 3. Eliminated Magic Strings
- Extracted hard-coded plain text default passwords (such as `'Company@2026'`, `'Stax@123'`, `'K@2026'`) from:
  - `company-import.service.ts`
  - `stax-legacy-migration.service.ts`
  - `database.seeder.ts`
- These are now securely accessed via `process.env.SEED_DEFAULT_PASSWORD`, defaulting cleanly without polluting the source file with secrets.

### 4. Hardcoded Rule & Typo Cleanup
- Fixed the mock mechanism in `BootstrapService` limiting approvals specifically to `superadmin` users to align with the frontend UI while not violating domain purity.
- Updated the Kafka Event Bus adapter logger to accurately log using the `[Kafka]` prefix as opposed to `[RabbitMQ]`.

## Verification Results
- All structural updates have successfully compiled (`npx tsc --noEmit` exited without errors). The business logic invariants are now strictly enforceable by code structure exactly as specified by the architectural report.
