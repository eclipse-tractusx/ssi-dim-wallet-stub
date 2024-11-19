# Wallet Stub Application Integration Guide

This document provides instructions for integrating the wallet stub application with other
applications: `portal-backend`, `ssi-credential-issuer`, and `edc`.

## Portal Backend Integration

Set the following environment variables for the `portal-backend` to integrate with the wallet stub application:

| Name                                   | Description                | Expected Value              |
|----------------------------------------|----------------------------|-----------------------------|
| dim.clientId                           | Client ID for Wallet       | BPNL000000000000            |
| dim.clientSecret                       | Client Secret for Wallet   | BPNL000000000000            |
| dim.grantType                          | Grant Type                 | client_credentials          |
| dim.scope                              | Scope                      | openid                      |
| dim.baseAddress                        | Base Address               | http://localhost            |
| dim.universalResolverAddress           | Universal Resolver Address | https://dev.uniresolver.io/ |
| decentralIdentityManagementAuthAddress | Auth Address               | http://localhost/api/sts    |

## SSI Credential Issuer Integration

Set the following environment variables for the `ssi-credential-issuer` to integrate with the wallet stub application:

| Name                     | Description      | Expected Value                                                                             |
|--------------------------|------------------|--------------------------------------------------------------------------------------------|
| walletAddress            | Wallet URL       | http://localhost                                                                           |
| walletTokenAddress       | Wallet OAuth URL | http://localhost/oauth/token                                                               |
| credential.issuerDid     | Issuer DID       | did:web:locahost:BPNL000000000000                                                          |
| credential.issuerBpn     | Issuer BPN       | BPNL000000000000                                                                           |
| credential.statusListUrl | Status List URL  | http://localhost/api/dim/status-list/BPNL000000000000/8a6c7486-1e1f-4555-bdd2-1a178182651e |

## EDC Integration

Set the following environment variables for the `edc` to integrate with the wallet stub application:

| Name                                  | Description                                  | Expected Value                     |
|---------------------------------------|----------------------------------------------|------------------------------------|
| edc.iam.issuer.id                     | IAM Issuer ID                                | did:web:localhost:BPNL000000000000 |
| edc.iam.trusted-issuer.1-issuer.id    | Trusted Issuer ID                            | did:web:localhost:BPNL000000000000 |
| edc.iam.sts.dim.url                   | DIM URL                                      | http://localhost/api/sts           |
| edc.iam.sts.oauth.token.url           | OAuth Token URL                              | http://localhost/oauth/token       |
| tx.edc.iam.iatp.credentialservice.url | IATP Credential Service URL                  | http://localhost/api               |
| edc.iam.sts.oauth.client.id           | OAuth Client ID                              | BPNL000000000000                   |
| edc.iam.sts.oauth.client.secret.alias | OAuth Client Secret Alias                    | BPNL000000000000                   |
| tx.edc.iam.iatp.bdrs.server.url       | BDRS server URL, it will be wallet stub host | http://localhost/api/v1/directory  |

## Notes

- Ensure that all values are correctly set to the wallet stub application.
- Update any missing or placeholder values with the actual configuration details.
- For any additional configuration or troubleshooting, refer to the respective service documentation.
- Ensure that wallets are created in SSI dim wallet stub application for both BPNs which are configured in both EDCs
- In configuration, ``localhost`` means wallet stub URL.
- If wallet stub is running other than 80 port then we need to use port forwarding or tunnel(i.e. https://tunnelmole.com/) as EDC will not resole DID document with the port.


## NOTICE

This work is licensed under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).

- SPDX-License-Identifier: Apache-2.0
- SPDX-FileCopyrightText: 2024 Contributors to the Eclipse Foundation
- Source URL: https://github.com/eclipse-tractusx/ssi-dim-wallet-stub
