# Implementation Plan: System Module Refactoring

This plan outlines the steps to refactor the `SystemModule` to adhere to Clean Architecture principles, as defined in `docs/STAX/context/`. We will decouple the `SystemController` from domain enums and business logic by introducing specialized Application Services.

## User Review Required

> [!IMPORTANT]
> **Decoupling Strategy**: We are moving internal UI flags and lookup logic out of the Controller. This might slightly change how you add new lookups in the future (you'll add them to the Service instead of the Controller).

> [!WARNING]
> **Cross-module Dependencies**: We will maintain imports to other modules for now in the Service layer, but we'll isolate them so the Controller remains clean and focused only on HTTP concerns.

## Proposed Changes

### 1. Application Layer (System Logic) [NEW]

We will create two new services to handle the logic currently "leaked" into the controller.

#### [NEW] [lookup.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/system/application/services/lookup.service.ts)
- Handles the collection and formatting of system-wide Enums and master data.
- Centralizes the "Knowledge" of available categories.

#### [NEW] [bootstrap.service.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/system/application/services/bootstrap.service.ts)
- Handles the generation of the initial App Context (User profile, Configs, UI Permissions).
- This service will eventually integrate with `RbacService` to provide real permission flags.

---

### 2. Infrastructure Layer (Wiring) [MODIFY]

#### [MODIFY] [system.module.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/system/system.module.ts)
- Register the new services as providers.

#### [MODIFY] [system.controller.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/system/infrastructure/controllers/system.controller.ts)
- Inject `LookupService` and `BootstrapService`.
- Remove all hardcoded logic and mock objects.
- Simplify methods to just call the services.

---

### 3. Core Shared Utils [MODIFY]

#### [MODIFY] [drizzle-pagination.util.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/core/shared/infrastructure/persistence/utils/drizzle-pagination.util.ts)
- Decouple common DB pagination logic from the HTTP DTO.
- Change `getLimitOffset` signature to accept a simple object `{ page?: number; limit?: number }`.

## Open Questions

- Should we implement a dynamic Registration pattern for Lookups now, or keep it simple with a centralized service for this phase? (Recommendation: Keep it simple for now, but well-isolated).

## Verification Plan

### Automated Tests
- No existing tests for this module found yet.
- I will verify the build by running `pnpm run start:dev` and checking for compilation errors.

### Manual Verification
- Verify that the `/system/bootstrap` and `/system/lookups` endpoints still return the same JSON structure as before to avoid breaking the Frontend.
