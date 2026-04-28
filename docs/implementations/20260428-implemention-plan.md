# Implementation Plan: Completing Interaction & Management APIs

This plan aims to fill the gaps in the Backend's API surface to support a professional, "Backend-Driven UI" for STAX. We will focus on Boss-Employee interactions, advanced scoping, and actionable metadata.

## User Review Required

> [!IMPORTANT]
> **Actionable Metadata**: We will add a `_actions` field to major entities (Lead, Finote). This will centralize logic that was previously calculated on the Frontend.
> **Breaking Change Alert**: The DTOs for `Lead` and `Finote` might be updated to include this field.

## Proposed Changes

### 1. CRM Module (Management & Assignment)

#### [MODIFY] [lead.controller.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/crm/infrastructure/controllers/lead.controller.ts)
- Add `PATCH /crm/leads/:id/assign`: Allows Managers to assign/reassign leads to staff.
- Add `GET /crm/leads/stats`: Summary statistics for managers (total leads, conversion by staff).
- Update return types to include `_actions` (canEdit, canAssign, canClose).

### 2. Accounting Module (Approval Flow)

#### [MODIFY] [finote.controller.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/accounting/infrastructure/controllers/finote.controller.ts)
- Add `POST /accounting/finotes/:id/approve`: Allows Managers to approve pending Finotes.
- Add `POST /accounting/finotes/:id/reject`: Allows Managers to reject Finotes with a reason.
- Add `GET /accounting/finotes/pending`: A dedicated view for managers to see items requiring action.
- Update return types to include `_actions` (canApprove, canReject, canPay).

### 3. System Module (Advanced UX)

#### [MODIFY] [system.controller.ts](file:///home/ka/Repos/github.com/trongnghiango/rbac-nest-project/src/modules/system/infrastructure/controllers/system.controller.ts)
- Add `GET /system/my-team/summary`: Cross-module performance summary for Leaders.

### 4. Shared DTOs & Domain Logic

- Add `ActionableDto` in `core/shared` to standardize the `_actions` structure.
- Update `Lead` and `Finote` domain entities/services to handle the assignment and approval status changes.

---

## Documentation Updates

After each phase, the following documents will be updated:
- `docs/STAX/context/ui-integration.md`: Reflecting the new `_actions` standard.
- `docs/STAX/ideas/frontend-portal.md`: Adding the new worklows and endpoints.
- `docs/STAX/context/changelog.md`: Logging the functional enhancements.

## Verification Plan

### Automated Tests
- Create unit tests for Assignment and Approval services.
- Verify through build and manual smoke tests.

### Manual Verification
- Check Swagger/OpenAPI docs for the new endpoints.
- Verify `_actions` correctly reflects permissions (e.g., Staff cannot see `canApprove: true`).
