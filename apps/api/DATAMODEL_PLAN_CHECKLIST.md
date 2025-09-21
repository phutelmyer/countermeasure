# Data Model Reorganization Plan & Checklist

## Overview
This document outlines the hybrid organization approach for restructuring the Countermeasure API data models. The plan combines subdirectory organization for logical grouping with separate files for individual models to improve maintainability, scalability, and developer experience.

## Current State Analysis

### Current Structure (Flat)
```
src/db/models/
├── __init__.py
├── actor.py (211 lines - contains Actor, Campaign, MalwareFamily)
├── base.py
├── category.py
├── detection.py (contains Detection + 3 mapping models)
├── mitre.py (contains MitreTactic, MitreTechnique)
├── severity.py
├── tag.py
├── tenant.py
├── user.py
└── ...
```

### Issues with Current Structure
- [ ] actor.py contains 3 distinct models (Actor, Campaign, MalwareFamily)
- [ ] detection.py contains 4 models (Detection + mapping tables)
- [ ] mitre.py contains 2 models (MitreTactic, MitreTechnique)
- [ ] Flat structure makes it hard to understand relationships
- [ ] No clear domain boundaries

## Proposed Hybrid Structure

### Target Directory Organization
```
src/db/models/
├── __init__.py (main exports for backward compatibility)
├── base.py (keep at root - foundation classes)
│
├── intel/                  # Threat intelligence entities
│   ├── __init__.py
│   ├── actor.py           # Threat actors/groups only
│   ├── campaign.py        # Operations & campaigns
│   ├── malware.py         # Malware families & tools (renamed from MalwareFamily)
│   ├── indicator.py       # IOCs & observables (future)
│   └── intelligence.py    # Reports & assessments (future)
│
├── detection/             # Detection & rule management
│   ├── __init__.py
│   └── detection.py       # Detection rules + mappings (keep together)
│
├── framework/             # External frameworks & standards
│   ├── __init__.py
│   ├── mitre.py          # MitreTactic, MitreTechnique
│   └── stix.py           # STIX objects (future)
│
├── system/                # Infrastructure & system models
│   ├── __init__.py
│   ├── user.py           # User model
│   ├── tenant.py         # Tenant model
│   └── audit.py          # Audit logs (future)
│
├── taxonomy/              # Classification & metadata
│   ├── __init__.py
│   ├── category.py       # Category model
│   ├── tag.py            # Tag model
│   └── severity.py       # Severity model
│
└── (future domains)       # Consistent domain organization
    ├── visibility/        # Endpoint data, sensors, alerts
    ├── prevention/        # Policies, blocks, mitigations
    └── response/          # Incidents, playbooks, workflows
```

## Migration Checklist

### Phase 1: Preparation
- [ ] Create comprehensive test suite for all model operations
- [ ] Document all current import paths across the codebase
- [ ] Create rollback plan
- [ ] Set up feature branch: `feature/model-reorganization`

### Phase 2: Create Directory Structure
- [ ] Create subdirectories:
  - [ ] `mkdir -p src/db/models/intel`
  - [ ] `mkdir -p src/db/models/system`
  - [ ] `mkdir -p src/db/models/detection`
  - [ ] `mkdir -p src/db/models/framework`
  - [ ] `mkdir -p src/db/models/taxonomy`
- [ ] Create `__init__.py` files in each subdirectory

### Phase 3: Split and Move Models

#### 3.1 System Models
- [ ] Move `tenant.py` to `system/tenant.py`
- [ ] Move `user.py` to `system/user.py`
- [ ] Update `system/__init__.py`:
  ```python
  from .tenant import Tenant
  from .user import User

  __all__ = ["Tenant", "User"]
  ```

#### 3.2 Intel Threat Intelligence Models
- [ ] Split `actor.py`:
  - [ ] Keep only Actor model in `intel/actor.py`
  - [ ] Move Campaign model to `intel/campaign.py`
  - [ ] Move MalwareFamily to `intel/malware.py` and rename class to `Malware`
- [ ] Update relationships:
  - [ ] Actor: Update relationship imports for Campaign and Malware
  - [ ] Campaign: Add proper imports and relationships
  - [ ] Malware: Add proper imports and relationships
- [ ] Update `intel/__init__.py`:
  ```python
  from .actor import Actor
  from .campaign import Campaign
  from .malware import Malware

  __all__ = ["Actor", "Campaign", "Malware"]
  ```

#### 3.3 Detection Models
- [ ] Keep `detection.py` as single file in `detection/detection.py`
- [ ] Update `detection/__init__.py`:
  ```python
  from .detection import (
      Detection,
      DetectionCategoryMapping,
      DetectionTagMapping,
      DetectionMitreMapping
  )

  __all__ = [
      "Detection",
      "DetectionCategoryMapping",
      "DetectionTagMapping",
      "DetectionMitreMapping"
  ]
  ```

#### 3.4 Framework Models
- [ ] Move `mitre.py` to `framework/mitre.py` (keep models together)
- [ ] Update `framework/__init__.py`:
  ```python
  from .mitre import MitreTactic, MitreTechnique

  __all__ = ["MitreTactic", "MitreTechnique"]
  ```

#### 3.5 Taxonomy Models
- [ ] Move `category.py` to `taxonomy/category.py`
- [ ] Move `tag.py` to `taxonomy/tag.py`
- [ ] Move `severity.py` to `taxonomy/severity.py`
- [ ] Update `taxonomy/__init__.py`:
  ```python
  from .category import Category
  from .tag import Tag
  from .severity import Severity

  __all__ = ["Category", "Tag", "Severity"]
  ```

### Phase 4: Update Import Paths

#### 4.1 Update Internal Model Imports
- [ ] Update imports in `intel/actor.py`:
  ```python
  from ..base import Base, TenantMixin, MetadataMixin
  from ..system.user import User
  from .campaign import Campaign
  from .malware import Malware
  ```

- [ ] Update imports in `intel/campaign.py`:
  ```python
  from ..base import Base
  from .actor import Actor
  ```

- [ ] Update imports in `intel/malware.py`:
  ```python
  from ..base import Base
  from .actor import Actor
  ```

- [ ] Update imports in `detection/detection.py`:
  ```python
  from ..base import Base, TenantMixin, MetadataMixin
  from ..system.user import User
  from ..taxonomy.severity import Severity
  from ..taxonomy.category import Category
  from ..taxonomy.tag import Tag
  from ..framework.mitre import MitreTechnique
  ```

#### 4.2 Update Service Layer Imports
- [ ] Update `src/services/actor_service.py`:
  ```python
  from src.db.models.intel import Actor, Campaign, Malware
  # OR with backward compatibility:
  from src.db.models import Actor, Campaign, Malware
  ```

- [ ] Update `src/services/detection_service.py`:
  ```python
  from src.db.models.detection import Detection
  from src.db.models.taxonomy import Category, Tag, Severity
  ```

#### 4.3 Update Seed Data Imports
- [ ] Update `src/db/seed_data/seed_actors.py`:
  ```python
  from src.db.models.intel import Actor, Campaign, Malware
  from src.db.models.system import Tenant
  ```

- [ ] Update `src/db/init_db.py`:
  ```python
  from src.db.models.system import Tenant, User
  ```

### Phase 5: Maintain Backward Compatibility

#### 5.1 Update Root __init__.py
- [ ] Update `src/db/models/__init__.py` to re-export all models:
  ```python
  # System models
  from .system.tenant import Tenant
  from .system.user import User

  # Intel threat intelligence models
  from .intel.actor import Actor
  from .intel.campaign import Campaign
  from .intel.malware import Malware

  # Detection models
  from .detection.detection import (
      Detection,
      DetectionCategoryMapping,
      DetectionTagMapping,
      DetectionMitreMapping
  )

  # Framework models
  from .framework.mitre import MitreTactic, MitreTechnique

  # Taxonomy models
  from .taxonomy.category import Category
  from .taxonomy.tag import Tag
  from .taxonomy.severity import Severity

  __all__ = [
      # System
      "Tenant", "User",
      # Intel threat intelligence
      "Actor", "Campaign", "Malware",
      # Detection
      "Detection", "DetectionCategoryMapping",
      "DetectionTagMapping", "DetectionMitreMapping",
      # Framework
      "MitreTactic", "MitreTechnique",
      # Taxonomy
      "Category", "Tag", "Severity",
  ]
  ```

### Phase 6: Database Migrations

#### 6.1 Handle Rename: MalwareFamily → Malware
- [ ] Create Alembic migration to rename table (if using migrations):
  ```sql
  ALTER TABLE malware_families RENAME TO malware;
  ```
- [ ] Update any foreign key constraints referencing `malware_families`
- [ ] Update indexes if needed

#### 6.2 Add Missing Fields
- [ ] Add `created_by` and `updated_by` to Campaign model
- [ ] Add `created_by` and `updated_by` to Malware model
- [ ] Create migration for new columns

### Phase 7: Testing & Validation

#### 7.1 Unit Tests
- [ ] Run all existing model tests
- [ ] Test all import paths work correctly
- [ ] Test relationships between models still function
- [ ] Test database operations (CRUD) for each model

#### 7.2 Integration Tests
- [ ] Test service layer with new imports
- [ ] Test API endpoints still function
- [ ] Test seed data scripts work
- [ ] Test database initialization

#### 7.3 Performance Tests
- [ ] Verify no performance regression
- [ ] Check import times
- [ ] Monitor memory usage

### Phase 8: Documentation

- [ ] Update model documentation with new structure
- [ ] Update import examples in README
- [ ] Document the organization pattern for new models
- [ ] Create ADR (Architecture Decision Record) for this change

### Phase 9: Deployment

- [ ] Merge to main branch after approval
- [ ] Tag release with model reorganization
- [ ] Update deployment documentation
- [ ] Monitor for any issues in staging/production

## Benefits of This Approach

### Immediate Benefits
1. **Better Organization**: Models grouped by domain
2. **Easier Navigation**: Developers can find models faster
3. **Clearer Boundaries**: Domain separation is explicit
4. **Smaller Files**: Each file contains single responsibility

### Long-term Benefits
1. **Scalability**: Easy to add new models in appropriate subdirectories
2. **Maintainability**: Changes isolated to specific domains
3. **Team Collaboration**: Different teams can own different subdirectories
4. **Testing**: Easier to test specific domains in isolation

## Rollback Plan

If issues arise during migration:

1. **Git Rollback**:
   ```bash
   git checkout main
   git branch -D feature/model-reorganization
   ```

2. **Database Rollback** (if schema changed):
   ```bash
   alembic downgrade -1
   ```

3. **Service Restart**:
   ```bash
   docker-compose down
   docker-compose up -d
   ```

## Success Criteria

- [ ] All tests pass (100% pass rate)
- [ ] API endpoints functional
- [ ] No performance degradation
- [ ] Database operations work correctly
- [ ] Seed data loads successfully
- [ ] No import errors
- [ ] Documentation updated

## Timeline Estimate

- **Phase 1-2**: 1 hour (preparation and structure creation)
- **Phase 3-4**: 2-3 hours (model splitting and import updates)
- **Phase 5-6**: 1-2 hours (backward compatibility and migrations)
- **Phase 7**: 1-2 hours (testing)
- **Phase 8-9**: 1 hour (documentation and deployment)

**Total Estimated Time**: 6-9 hours

## Notes

- Consider doing this migration during a low-traffic period
- Have a team member review all changes before merging
- Consider feature flagging if gradual rollout needed
- Monitor error rates closely after deployment

## Related TODOs from Codebase

From our analysis, these TODOs should be addressed during reorganization:

1. **MITRE Foreign Key Constraints** (from `mitre.py`):
   - Re-enable self-referencing relationships
   - Fix detection_mappings relationship

2. **Campaign/Malware Audit Fields** (from `seed_actors.py`):
   - Add `created_by` and `updated_by` fields to models

3. **MITRE Data Seeding** (from `init_db.py`):
   - Fix foreign key constraints to enable seeding

These can be addressed in Phase 6 during database migrations.