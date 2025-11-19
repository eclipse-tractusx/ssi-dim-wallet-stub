# Migration Guides

This directory contains comprehensive migration guides for the SSI DIM Wallet Stub application.

## Available Guides

### [Quick Migration Guide](./BITNAMI_TO_CLOUDPIRATES_MIGRATION_GUIDE.md) ⭐ **Start Here**

**Purpose**: Concise step-by-step guide for migrating from Bitnami PostgreSQL 15.4 to CloudPirates PostgreSQL 18.0

**When to use this guide**:
- You need a quick reference during migration
- You've already reviewed the full detailed guide
- You want clear, actionable commands

**Features**:
- 7 simple steps with commands
- 15-60 minute estimated timeline
- Quick rollback procedure
- Troubleshooting table

**Target Audience**: Anyone performing the migration

---

### [Detailed Migration Guide](./BITNAMI_TO_CLOUDPIRATES_MIGRATION_GUIDE.md)

**Purpose**: Comprehensive documentation with full explanations and advanced scenarios

**When to use this guide**:
- First time performing this migration
- Need detailed explanations of each step
- Troubleshooting complex issues
- Planning production migration strategy

**Key Features**:
- Complete backup and restore procedures
- Verification steps at each phase
- Troubleshooting common issues
- Rollback procedures
- Production checklist
- Estimated timelines based on database size

**Target Audience**:
- DevOps engineers
- System administrators
- Database administrators
- Anyone responsible for production migrations

---

## Migration Strategy Overview

All guides in this directory follow a similar strategy:

1. **Pre-Migration**
   - Verify current state
   - Document existing data
   - Create comprehensive backup

2. **Migration**
   - Stop current deployment
   - Deploy new configuration
   - Restore data

3. **Verification**
   - Verify database version
   - Verify data integrity
   - Test application functionality

4. **Post-Migration**
   - Monitor for issues
   - Document migration
   - Archive backups

## NOTICE

This work is licensed under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).

- SPDX-License-Identifier: Apache-2.0
- SPDX-FileCopyrightText: 2024 Contributors to the Eclipse Foundation
- Source URL: https://github.com/eclipse-tractusx/ssi-dim-wallet-stub
