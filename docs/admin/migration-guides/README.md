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
- ✅ **Tested and validated** (see [Test Results](./TEST_RESULTS.md))

**Target Audience**: Anyone performing the migration

---

### [Detailed Migration Guide](./bitnami-postgres15-to-cloudpirates-postgres18.md)

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

### [Migration Test Report](./BITNAMI_TO_CLOUDPIRATES_MIGRATION_TEST.md)

**Purpose**: Comprehensive test results showing what works and what doesn't during automatic migration attempts

**When to use this guide**:
- Understanding why manual migration is required
- Learning from test results and findings
- Reference for root cause analysis

---

### [Test Results - Quick Guide Validation](./TEST_RESULTS.md) ✅

**Purpose**: Real-world test results validating the quick migration guide

**Contains**:
- Complete test execution log
- Data integrity verification
- Actual vs estimated timeline
- Key findings and discoveries
- Production readiness assessment

**Status**: ✅ **Guide validated and production-ready**

---

## Quick Reference

### When is Manual Migration Required?

Manual migration is **required** when:
- ✅ Migrating from Bitnami to CloudPirates charts
- ✅ Upgrading across PostgreSQL major versions (e.g., 15.x → 18.x)
- ✅ Existing production data must be preserved
- ✅ Different data directory structures between charts

### When is Manual Migration NOT Required?

Manual migration is **not required** when:
- ❌ Fresh installation with no existing data
- ❌ Development/testing environment where data loss is acceptable
- ❌ Staying within the same chart and PostgreSQL major version

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

---

## Best Practices

### Before Starting Any Migration

1. **Test in Non-Production First**
   - Never perform your first migration in production
   - Test the entire procedure in development/staging
   - Document any issues and solutions

2. **Schedule Adequate Maintenance Window**
   - Review estimated timelines in the specific guide
   - Add 50% buffer time for unexpected issues
   - Communicate clearly with stakeholders

3. **Verify Backup Quality**
   - Always verify backup file integrity
   - Test restore procedure before production migration
   - Keep multiple backup copies

4. **Prepare Rollback Plan**
   - Document rollback procedure
   - Test rollback in non-production
   - Have rollback decision criteria ready

### During Migration

1. **Follow the Guide Step-by-Step**
   - Don't skip verification steps
   - Document any deviations from the guide
   - Save all command outputs

2. **Monitor Continuously**
   - Watch logs during restore
   - Check for errors immediately
   - Have team available for support

3. **Document Everything**
   - Save all command outputs
   - Note any issues encountered
   - Record actual timelines

### After Migration

1. **Extended Monitoring**
   - Monitor for 24-48 hours minimum
   - Watch for data inconsistencies
   - Check application performance

2. **Validate Thoroughly**
   - Run full application test suite
   - Verify all features work correctly
   - Check data integrity

3. **Archive Documentation**
   - Save migration logs
   - Document lessons learned
   - Update runbooks

---

## Support and Resources

### Internal Resources
- [Bitnami to CloudPirates Migration Test Report](../BITNAMI_TO_CLOUDPIRATES_MIGRATION_TEST.md)
- [PostgreSQL Migration Overview](../POSTGRESQL_MIGRATION.md)
- [Architecture Documentation](../../architecture/main.md)

### External Resources
- [PostgreSQL Official Documentation](https://www.postgresql.org/docs/)
- [CloudPirates Helm Charts](https://github.com/CloudPirates-io/helm-charts)
- [Kubernetes Backup Best Practices](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)

---

## Contributing to Migration Guides

### Adding a New Guide

When creating a new migration guide, include:

1. **Overview Section**
   - What is being migrated
   - Why manual migration is needed
   - Estimated timelines

2. **Prerequisites**
   - Required tools
   - Required access
   - Required knowledge

3. **Step-by-Step Procedure**
   - Numbered phases
   - Clear commands with explanations
   - Expected outputs
   - Verification steps

4. **Troubleshooting Section**
   - Common issues
   - Solutions
   - When to rollback

5. **Rollback Procedure**
   - Clear rollback steps
   - Decision criteria
   - Recovery procedures

6. **Checklist**
   - Pre-migration checklist
   - During migration checklist
   - Post-migration checklist

### Guide Template Structure

```markdown
# Migration Guide: [Source] to [Target]

## Overview
## Prerequisites
## Migration Strategy
## Estimated Timeline
## Step-by-Step Procedure
  ### Phase 1: Pre-Migration
  ### Phase 2: Backup
  ### Phase 3: Deploy New
  ### Phase 4: Restore
  ### Phase 5: Verify
  ### Phase 6: Test
  ### Phase 7: Post-Migration
## Rollback Procedure
## Troubleshooting
## Checklist
## Additional Resources
```

---

## Migration Support

For questions or issues with migrations:

1. **Review the Specific Guide**: Most questions are answered in the guide
2. **Check Troubleshooting Section**: Common issues and solutions documented
3. **Review Test Reports**: See what was tested and what issues were found
4. **Consult DevOps Team**: For environment-specific questions

---

**Last Updated**: October 28, 2025  
**Maintainer**: DevOps Team
