# Wallet Stub Application Integration Guide

This document provides instructions for integrating the wallet stub application with other
applications: `portal-backend`, `ssi-credential-issuer`, `edc`, and `bpn-did-resolution-service`.

## Portal Backend Integration

Set the following environment variables for the `portal-backend` to integrate with the wallet stub application:

| Name                                   | Description                | Expected Value              |
|----------------------------------------|----------------------------|-----------------------------|
| dim.clientId                           | Client ID for Wallet       | BPNL000000000000            |
| dim.clientSecret                       | Client Secret for Wallet   | BPNL000000000000            |
| dim.grantType                          | Grant Type                 | client_credentials          |
| dim.scope                              | Scope                      | openid                      |
| dim.baseAddress                        | Base Address               | https://localhost           |
| dim.universalResolverAddress           | Universal Resolver Address | https://dev.uniresolver.io/ |
| decentralIdentityManagementAuthAddress | Auth Address               | https://localhost/api/sts   |

## SSI Credential Issuer Integration

Set the following environment variables for the `ssi-credential-issuer` to integrate with the wallet stub application:

| Name                     | Description      | Expected Value                                                                              |
|--------------------------|------------------|---------------------------------------------------------------------------------------------|
| walletAddress            | Wallet URL       | https://localhost                                                                           |
| walletTokenAddress       | Wallet OAuth URL | https://localhost/oauth/token                                                               |
| credential.issuerDid     | Issuer DID       | did:web:locahost:BPNL000000000000                                                           |
| credential.issuerBpn     | Issuer BPN       | BPNL000000000000                                                                            |
| credential.statusListUrl | Status List URL  | https://localhost/api/dim/status-list/BPNL000000000000/8a6c7486-1e1f-4555-bdd2-1a178182651e |

## EDC Integration

Set the following environment variables for the `edc` to integrate with the wallet stub application:

| Name                                  | Description                 | Expected Value                     |
|---------------------------------------|-----------------------------|------------------------------------|
| edc.iam.issuer.id                     | IAM Issuer ID               | did:web:localhost:BPNL000000000000 |
| edc.iam.trusted-issuer.1-issuer.id    | Trusted Issuer ID           | did:web:localhost:BPNL000000000000 |
| edc.iam.sts.dim.url                   | DIM URL                     | https://localhost/api/sts          |
| edc.iam.sts.oauth.token.url           | OAuth Token URL             | https://localhost/oauth/token      |
| tx.edc.iam.iatp.credentialservice.url | IATP Credential Service URL | https://localhost/api              |
| edc.iam.sts.oauth.client.id           | OAuth Client ID             | BPNL000000000000                   |
| edc.iam.sts.oauth.client.secret.alias | OAuth Client Secret Alias   | BPNL000000000000                   |

## BPN DID Resolution Service Integration

Set the following environment variables for the `bpn-did-resolution-service` to integrate with the wallet stub
application:

| Name            | Description     | Expected Value                         |
|-----------------|-----------------|----------------------------------------|
| BASE_WALLET_BPN | Base Wallet BPN | BPNL000000000000                       |
| BASE_WALLET_DID | Base Wallet DID | did:web:localhost:BPNL000000000000     |
| trustedIssuers  | Trusted Issuers | ["did:web:localhost:BPNL000000000000"] |

## Notes

- Ensure that all values are correctly set to the wallet stub application.
- Update any missing or placeholder values with the actual configuration details.
- For any additional configuration or troubleshooting, refer to the respective service documentation.

