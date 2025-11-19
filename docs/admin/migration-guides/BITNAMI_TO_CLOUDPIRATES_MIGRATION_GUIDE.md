# Quick Migration Guide: Bitnami PostgreSQL 15 → CloudPirates PostgreSQL 18

**Estimated Time**: 15-60 minutes depending on database size

## Prerequisites
- Kubernetes cluster access with `kubectl`
- Helm 3.x installed
- Maintenance window scheduled

---

## Migration Steps

### 1. Backup Current Data

```bash
# Navigate to backup directory
mkdir -p ~/wallet-migration-backup && cd ~/wallet-migration-backup
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)

# Create full backup
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword pg_dumpall -U postgres" > backup_${BACKUP_DATE}.sql

# Verify backup
ls -lh backup_${BACKUP_DATE}.sql
head -n 20 backup_${BACKUP_DATE}.sql

# Document current data
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword psql -U postgres -c 'SELECT COUNT(*) FROM key_pair;'"
```

**Expected**: File size > 0, should show SQL statements

---

### 2. Stop Current Deployment

```bash
# Uninstall Bitnami deployment
cd /path/to/ssi-dim-wallet-stub/charts/ssi-dim-wallet-stub
helm uninstall ssi-dim-wallet-test --namespace wallet

# Delete old PVC (ONLY after backup is verified!)
kubectl delete pvc data-wallet-postgres-0 -n wallet

# Verify PVC is deleted
kubectl get pvc -n wallet
```

**Expected**: No resources found

---

### 3. Update Chart Configuration

Update `Chart.yaml`:
```yaml
dependencies:
  - name: postgres
    repository: oci://registry-1.docker.io/cloudpirates
    version: 0.11.0
    condition: postgresql.enabled
    alias: postgresql
```

Update `values.yaml`:
```yaml
postgresql:
  fullnameOverride: wallet-postgres
  enabled: true
  image:
    registry: docker.io
    repository: postgres
    tag: "18.0@sha256:1ffc019dae94eca6b09a49ca67d37398951346de3c3d0cfe23d8d4ca33da83fb"
  persistence:
    enabled: true
    size: 10Gi
    storageClass: standard
```

---

### 4. Deploy CloudPirates PostgreSQL

```bash
# Update dependencies
helm dependency update

# Install CloudPirates chart
helm install ssi-dim-wallet-test . --namespace wallet --create-namespace

# Wait for pods to be ready
kubectl wait --for=condition=ready pod --all -n wallet --timeout=300s

# Verify PostgreSQL 18.0
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword psql -U postgres -c 'SELECT version();'"
```

**Expected**: PostgreSQL 18.0 (Debian 18.0-1.pgdg13+3)

---

### 5. Restore Data

```bash
# Navigate to backup directory
cd ~/wallet-migration-backup

# IMPORTANT: Truncate existing tables to avoid duplicate key errors
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword psql -U postgres -c \
  'TRUNCATE TABLE key_pair, did_document, holder_credential, holder_credential_as_jwt, jwt_credential, custom_credential CASCADE;'"

# Restore backup (this will take time for large databases)
cat backup_${BACKUP_DATE}.sql | kubectl exec -i -n wallet wallet-postgres-0 -- \
  bash -c "PGPASSWORD=postgrespassword psql -U postgres"

# Note: You may see warnings like "database already exists" - this is normal
```

**Monitor progress**: Watch for `COPY 4` messages indicating data rows are being inserted

---

### 6. Verify Migration

```bash
# Verify PostgreSQL version
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword psql -U postgres -c 'SELECT version();'"

# Verify data counts
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword psql -U postgres -c 'SELECT COUNT(*) FROM key_pair;'"

# List BPNs
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword psql -U postgres -c 'SELECT bpn FROM key_pair ORDER BY bpn;'"

# Verify tables
kubectl exec -n wallet wallet-postgres-0 -- bash -c \
  "PGPASSWORD=postgrespassword psql -U postgres -c '\dt'"
```

**Expected**: All data should match pre-migration counts

---

### 7. Test Application

```bash
# Check application health
APP_POD=$(kubectl get pod -n wallet -l app=ssi-dim-wallet-stub -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n wallet $APP_POD -- curl -s http://localhost:8080/actuator/health

# Check logs
kubectl logs -n wallet $APP_POD --tail=50
```

**Expected**: `{"status":"UP"}`

---

## Quick Rollback

If issues occur:

```bash
# 1. Stop CloudPirates
helm uninstall ssi-dim-wallet-test --namespace wallet
kubectl delete pvc data-wallet-postgres-0 -n wallet

# 2. Restore Bitnami chart configuration
# (revert Chart.yaml and values.yaml changes)

# 3. Deploy Bitnami
helm dependency update
helm install ssi-dim-wallet-test . --namespace wallet

# 4. Restore backup
cat backup_${BACKUP_DATE}.sql | kubectl exec -i -n wallet wallet-postgres-0 -- \
  bash -c "PGPASSWORD=postgrespassword psql -U postgres"
```

## NOTICE

This work is licensed under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).

- SPDX-License-Identifier: Apache-2.0
- SPDX-FileCopyrightText: 2024 Contributors to the Eclipse Foundation
- Source URL: https://github.com/eclipse-tractusx/ssi-dim-wallet-stub
