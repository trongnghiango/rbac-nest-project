# Clean Architecture Review Fixes Implementation Plan

This plan addresses the micro-level violations mentioned in the architectural review, ensuring the codebase fully aligns with Clean Architecture and Domain-Driven Design principles.

## Proposed Changes

---

### Domain Layer (Accounting)

#### [MODIFY] [finote.entity.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/accounting/domain/entities/finote.entity.ts)
- Change `status` and `reviewerId` to private properties (`_status` and `_reviewerId`).
- Add getters for `status` and `reviewerId`.
- Add `approve(reviewerId: number)` method with domain logic validation.
- Add `reject(reviewerId: number, reason: string)` method with domain logic validation.
- Update `recordPayment` to use `this._status`.
- Update constructor to initialize `_status` and `_reviewerId`.

### Application Layer (Accounting)

#### [MODIFY] [finote.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/accounting/application/services/finote.service.ts)
- Update `approve` to delegate to `finote.approve(reviewerId)` instead of modifying state directly.
- Update `reject` to delegate to `finote.reject(reviewerId, reason)` instead of modifying state directly.

---

### Mappers (Employee)

#### [MODIFY] [employee.mapper.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/employee/infrastructure/persistence/mappers/employee.mapper.ts)
- Simplify redundant ternary operations, specifically `raw.userId ? Number(raw.userId) : undefined` and related duplicate date checks.

---

### Migrations & Seeders

#### [MODIFY] [company-import.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/org-structure/application/services/company-import.service.ts)
- Replace magic password `'Company@2026'` with `process.env.SEED_DEFAULT_PASSWORD || 'Company@2026'`.

#### [MODIFY] [stax-legacy-migration.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/test/application/services/stax-legacy-migration.service.ts)
- Replace magic password `'Stax@123'` with `process.env.SEED_DEFAULT_PASSWORD || 'Stax@123'`.

#### [MODIFY] [database.seeder.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/test/seeders/database.seeder.ts)
- Replace magic password `'K@2026'` with `process.env.SEED_DEFAULT_PASSWORD || 'K@2026'`.

---

### System Services & Adapters

#### [MODIFY] [bootstrap.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/system/application/services/bootstrap.service.ts)
- Remove the hardcoded `canApproveFinotes` business logic rule check in `getUiPermissions`.

#### [MODIFY] [kafka-event-bus.adapter.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/core/shared/infrastructure/event-bus/adapters/kafka-event-bus.adapter.ts)
- Fix the logger prefix from `[RabbitMQ]` to `[Kafka]`.

## Open Questions
- For the `BootstrapService`, removing `canApproveFinotes` will break the mock for the Frontend. I will leave it as `false` or purely hardcode without relying on `user.username`, or perhaps default it to `true` temporarily. Please confirm if changing it to `false` is preferred to eliminate the business rule violation.

## Verification Plan
### Automated Tests
- Ensure tests still compile and run properly after modifying private properties.
### Manual Verification
- Check if project compiles.
