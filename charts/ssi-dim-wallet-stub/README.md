## Helm chart to deploy SSI DIM Wallet stub application

### Source Code

* <https://github.com/eclipse-tractusx/ssi-dim-wallet-stub>

### Requirements

| Repository | Name        | Version |
|------------|-------------|---------|
| https://charts.bitnami.com/bitnami | keycloak    | 22.1.0 |
| https://charts.bitnami.com/bitnami | postgresql  | 16.4.8 |

### Prerequisites
- Kubernetes 1.19+
- Helm 3.2.0+

### Install with released helm chart

```
helm repo add tractusx-dev https://eclipse-tractusx.github.io/charts/dev
helm repo update
helm install ssi-dim-wallet-stub tractusx-dev/ssi-dim-wallet-stub
```

### Install with local configuration

Step:
1. Create docker image locally with command `docker build -t ssi-dim-wallet-stub .`
2. Change docker image in values.yaml

```
helm dep up charts/ssi-dim-wallet-stub
kubectl create namespace wallet
helm install wallet-stub -n wallet charts/ssi-dim-wallet-stub
```

## Configuration Values

| Parameter                                     | Description                                                                            | Default Value                                     |
|-----------------------------------------------|----------------------------------------------------------------------------------------|---------------------------------------------------|
| `wallet.replicaCount`                         | The amount of replicas to run                                                          | `1`                                               |
| `wallet.host`                                 | Hostname for the wallet stub application                                               | `localhost`                                       |
| `wallet.nameSpace`                            | The namespace                                                                          | `"wallet"`                                        |
| `wallet.appName`                              | The application name                                                                   | `"ssi-dim-wallet-stub"`                           |
| `wallet.configName`                           | The configmap name                                                                     | `"ssi-dim-wallet-config"`                         |
| `wallet.serviceName`                          | The service name                                                                       | `"ssi-dim-wallet-service"`                        |
| `wallet.secretName`                           | The secret name                                                                        | `"ssi-dim-wallet-secret"`                         |
| `wallet.ingressName`                          | The ingress name                                                                       | `"ssi-dim-wallet-ingress"`                        |
| `wallet.image.repository`                     | Image repository                                                                       | `tractusx/managed-identity-wallet`                |
| `wallet.image.pullPolicy`                     | Pull policy for the image                                                              | `IfNotPresent`                                    |
| `wallet.image.tag`                            | Image tag (leave empty to use "appVersion" value from chart definition)                | `""`                                              |
| `wallet.resources.requests.cpu`               | CPU resource requests                                                                  | `250m`                                            |
| `wallet.resources.requests.memory`            | Memory resource requests                                                               | `512Mi`                                           |
| `wallet.resources.limits.cpu`                 | CPU resource limits                                                                    | `500m`                                            |
| `wallet.resources.limits.memory`              | Memory resource limits                                                                 | `1Gi`                                             |
| `wallet.livenessProbe.enabled`                | Enables/Disables the liveness probe                                                    | `true`                                            |
| `wallet.livenessProbe.failureThreshold`       | Number of failures before restarting the container                                     | `3`                                               |
| `wallet.livenessProbe.initialDelaySeconds`    | Initial delay before starting the liveness probe                                       | `20`                                              |
| `wallet.livenessProbe.timeoutSeconds`         | Timeout for the liveness probe                                                         | `15`                                              |
| `wallet.livenessProbe.periodSeconds`          | How often to perform the liveness probe                                                | `5`                                               |
| `wallet.readinessProbe.enabled`               | Enables/Disables the readiness probe                                                   | `true`                                            |
| `wallet.readinessProbe.failureThreshold`      | Number of failures before marking the Pod as Unready                                   | `3`                                               |
| `wallet.readinessProbe.initialDelaySeconds`   | Initial delay before starting the readiness probe                                      | `30`                                              |
| `wallet.readinessProbe.periodSeconds`         | How often to perform the readiness probe                                               | `5`                                               |
| `wallet.readinessProbe.successThreshold`      | Minimum consecutive successes for the readiness probe to be considered successful      | `1`                                               |
| `wallet.readinessProbe.timeoutSeconds`        | Timeout for the readiness probe                                                        | `5`                                               |
| `wallet.ingress.enabled`                      | Enable ingress configuration                                                           | `false`                                           |
| `wallet.ingress.tls`                          | Enable TLS for ingress                                                                 | `false`                                           |
| `wallet.ingress.urlPrefix`                    | URL prefix for the ingress                                                             | `/`                                               |
| `wallet.ingress.className`                    | Ingress class name                                                                     | `nginx`                                           |
| `wallet.ingress.annotations`                  | Annotations for the ingress                                                            | `{}`                                              |
| `wallet.swagger.ui.status`                    | Enable Swagger API documentation UI                                                    | `true`                                            |
| `wallet.swagger.apiDoc.status`                | Enable OpenAPI documentation                                                           | `true`                                            |
| `wallet.logLevel`                             | Application log level                                                                  | `"debug"`                                         |
| `wallet.environment`                          | Name of the landing zone (e.g., dev, int, prod)                                        | `"default"`                                       |
| `wallet.baseWalletBpn`                        | Operator Business Partner Number (BPN)                                                 | `"BPNL000000000000"`                              |
| `wallet.seeding.bpnList`                      | List of BPNs for which wallets will be seeded on application startup                   | `""`                                              |
| `wallet.didHost`                              | DID document host, used as part of the DID string (e.g., did:web:<didHost>)            | `"localhost"`                                     |
| `wallet.stubUrl`                              | Wallet stub server URL, used as part of the presentation query API in the DID document | `"http://localhost"`                              |
| `wallet.statusListVcId`                       | Default status list Verifiable Credential (VC) ID                                      | `"8a6c7486-1e1f-4555-bdd2-1a178182651e"`          |
| `wallet.tokenExpiryTime`                      | Token expiry time in seconds                                                           | `"5"`                                             |
| `wallet.portal.waitTime`                      | Wait time before pushing data to portal backend after wallet creation                  | `60`                                              |
| `wallet.portal.host`                          | Portal backend application host                                                        | `"http://localhost"`                              |
| `wallet.portal.clientId`                      | Keycloak client ID for accessing portal backend APIs                                   | `"client_id"`                                     |
| `wallet.portal.clientSecret`                  | Keycloak client secret for accessing portal backend APIs                               | `"client_secret"`                                 |
| `wallet.keycloak.realm`                       | Keycloak realm name                                                                    | `"CX-Central"`                                    |
| `wallet.keycloak.authServerUrl`               | Keycloak host URL                                                                      | `"http://localhost:28080/auth"`                   |
| `wallet.storageType`                          | The available storage options are: in-memory or database                               | `database`                                        |
| `wallet.postgresql.enabled`                   | Enable PostgraSQL driver, otherwise H2 will be use instead                             | `true`                                            |
| `wallet.postgresql.url`                       | The URL to connect to the database                                                     | `jdbc:postgresql://wallet-postgres:5432/postgres` |
| `wallet.postgresql.username`                  | The username to access the database                                                    | `postgrespassword`                                |
| `wallet.postgresql.password`                  | The password to access the database                                                    | `ClusterIP`                                       |
| `wallet.service.type`                         | Kubernetes service type                                                                | `ClusterIP`                                       |
| `wallet.service.port`                         | Kubernetes service port                                                                | `8080`                                            |
| `keycloak.enabled`                            | Enable Keycloak configuration                                                          | `false`                                           |
| `postgresql.fullnameOverride`                 | Overrides the default PostgreSQL release name with a custom name                       | `wallet-postgres`                                 |
| `postgresql.enabled`                          | Enables the deployment of the PostgreSQL instance                                      | `true`                                            |
| `postgresql.image.tag`                        | Specifies the PostgreSQL Docker image version to use                                   | `15-debian-11`                                    |
| `postgresql.configmap.name`                   | Name of the ConfigMap containing PostgreSQL configuration                              | `wallet-postgres-configmap`                       |
| `postgresql.auth.password`                    | Password for the PostgreSQL database user                                              | `postgrespassword`                                |
| `postgresql.auth.username`                    | Username for the PostgreSQL database                                                   | `postgres`                                        |
| `postgresql.primary.persistence.enabled`      | Enables persistent storage for PostgreSQL data                                         | `false`                                           |
| `postgresql.primary.persistence.size`         | Size of the persistent volume claim (PVC) for PostgreSQL storage                       | `10Gi`                                            |
| `postgresql.primary.persistence.storageClass` | Specifies the storage class to use for PostgreSQL persistence                          | `standard`                                        |
| `postgresql.primary.initdb.enabled`           | Enables the execution of initialization scripts on PostgreSQL startup                  | `true`                                            |
| `postgresql.primary.initdb.scripts.init.sql`  | SQL script to initialize the database                                                  | `{...}`                                           |
