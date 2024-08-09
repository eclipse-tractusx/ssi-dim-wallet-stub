## Helm char to deploy SSI DIM Wallet stub application

## Source Code

* <https://github.com/eclipse-tractusx/ssi-dim-wallet-stub>

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://charts.bitnami.com/bitnami | keycloak | 22.1.0 |

## Prerequisites
- Kubernetes 1.19+
- Helm 3.2.0+

## Install
```
helm dep up charts/ssi-dim-wallet-stub
kubectl create namespace wallet
helm install wallet-stub -n wallet charts/ssi-dim-wallet-stub
```

## Values

To be added
