# SSI DIM Wallet stub application

#### Note: *This application is meant and developed for local and integration testing only*

The Decentralized Identity Management (DIM) Wallet stub application provides REST APIs for below wallet functionality.

1. Setup Wallet and push Did document to portal backend
2. Issue Verifiable Credentials
3. Sign and get Verifiable Credentials by ID
4. Create Self issued (SI) token with scope and without scope
5. Query Verifiable Presentation
6. Create technical user for wallet to access APIs using OAuth flow
7. Request BPN Did mapping

This application can be used as a temporary wallet solution for local and integration testing.

This application is using Java 21 and Spring boot framework to serve REST APIs.

The DIM Wallet is part of the Self-Sovereign Identity (SSI) Flow of Eclipse Tractus-X.

### Run locally

#### Run in-memory

1. Update env variables in [application.yaml](runtimes/ssi-dim-wallet-stub-memory/src/main/resources/application.yaml)

| Name                         | Description                                                                      | Default value                                                                                                                                                          |
|------------------------------|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| APPLICATION_PORT             | Application port                                                                 | 8080                                                                                                                                                                   |
| ENABLE_SWAGGER_UI            | Enable the Swagger UI                                                            | true                                                                                                                                                                   |
| ENABLE_API_DOC               | Enable API documentation                                                         | true                                                                                                                                                                   |
| STUB_ENV                     | Environment(LZ) in with application is running.                                  | local                                                                                                                                                                  |
| BASE_WALLET_BPN              | Issuer BPN number                                                                | BPNL000000000000                                                                                                                                                       |
| SEED_WALLETS_BPN             | List of BPNs for which wallets will be seeded on application startup             | BPNL00000003AZQP,BPNL00000003AYRE                                                                                                                                      |
| DID_HOST                     | Did host                                                                         | localhost                                                                                                                                                              |
| STUB_URL                     | Wallet stub application host                                                     | https://localhost                                                                                                                                                      |
| STATUS_LIST_VC_ID            | VC id of status list credential of base wallet                                   | 8a6c7486-1e1f-4555-bdd2-1a178182651e                                                                                                                                   |
| TOKEN_EXPIRY_TIME            | JWT(STS, VC and VP) expiry time in minutes                                       | 5                                                                                                                                                                      |
| PORTAL_WAIT_TIME             | Wait time before we push did document to portal after wallet creation in seconds | 60                                                                                                                                                                     |
| PORTAL_HOST                  | Host of port backend application                                                 |                                                                                                                                                                        |
| PORTAL_CLIENT_ID             | Keycloak client_id to access portal API                                          |                                                                                                                                                                        |
| PORTAL_CLIENT_SECRET         | keycloak client_secret to access portal API                                      |                                                                                                                                                                        |
| PORTAL_REALM                 | keycloak realm                                                                   |                                                                                                                                                                        |
| PORTAL_AUTH_SERVER_URL       | Authentication server(keycloak)                                                  |                                                                                                                                                                        |
| APP_LOG_LEVEL                | Log level of application                                                         | DEBUG                                                                                                                                                                  |
| DID_DOCUMENT_CONTEXT_URLS    | Did document context URLs                                                        | https://www.w3.org/ns/did/v1, https://w3id.org/security/suites/jws-2020/v1, https://w3id.org/dspace-dcp/v1.0/dcp.jsonld, https://w3id.org/dspace/2025/1/context.jsonld |
| ISSUER_METADATA_CONTEXT_URLS | Issuer metadata context URLs                                                     | https://w3id.org/dspace-dcp/v1.0/dcp.jsonld, https://www.w3.org/2018/credentials/v1, https://w3id.org/catenax/credentials/v1.0.0                                       |

2. Run application using Gradle:

`./gradlew :runtimes:ssi-dim-wallet-stub-memory:clean :runtimes:ssi-dim-wallet-stub-memory:bootrun`

3. After successful running of the application, you can access swagger
   on  ``http://localhost:8080/ui/swagger-ui/index.html``

##### Deploy application using helm chart

Please refer [deploy using helm](charts/ssi-dim-wallet-stub-memory/README.md)

#### Run with Database

1. Update env variables in [application.yaml](runtimes/ssi-dim-wallet-stub/src/main/resources/application.yaml)

| Name                                | Description                                                                      | Default value                                                                                                                                                          |
|-------------------------------------|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| APPLICATION_PORT                    | Application port                                                                 | 8080                                                                                                                                                                   |
| ENABLE_SWAGGER_UI                   | Enable the Swagger UI                                                            | true                                                                                                                                                                   |
| ENABLE_API_DOC                      | Enable API documentation                                                         | true                                                                                                                                                                   |
| STUB_ENV                            | Environment(LZ) in with application is running.                                  | local                                                                                                                                                                  |
| BASE_WALLET_BPN                     | Issuer BPN number                                                                | BPNL000000000000                                                                                                                                                       |
| SEED_WALLETS_BPN                    | List of BPNs for which wallets will be seeded on application startup             | BPNL00000003AZQP,BPNL00000003AYRE                                                                                                                                      |
| DID_HOST                            | Did host                                                                         | localhost                                                                                                                                                              |
| STUB_URL                            | Wallet stub application host                                                     | https://localhost                                                                                                                                                      |
| STATUS_LIST_VC_ID                   | VC id of status list credential of base wallet                                   | 8a6c7486-1e1f-4555-bdd2-1a178182651e                                                                                                                                   |
| TOKEN_EXPIRY_TIME                   | JWT(STS, VC and VP) expiry time in minutes                                       | 5                                                                                                                                                                      |
| PORTAL_WAIT_TIME                    | Wait time before we push did document to portal after wallet creation in seconds | 60                                                                                                                                                                     |
| PORTAL_HOST                         | Host of port backend application                                                 |                                                                                                                                                                        |
| PORTAL_CLIENT_ID                    | Keycloak client_id to access portal API                                          |                                                                                                                                                                        |
| PORTAL_CLIENT_SECRET                | keycloak client_secret to access portal API                                      |                                                                                                                                                                        |
| PORTAL_REALM                        | keycloak realm                                                                   |                                                                                                                                                                        |
| PORTAL_AUTH_SERVER_URL              | Authentication server(keycloak)                                                  |                                                                                                                                                                        |
| APP_LOG_LEVEL                       | Log level of application                                                         | DEBUG                                                                                                                                                                  |
| SPRING_DATASOURCE_URL               | The URL to connect to the database                                               | jdbc:h2:mem:testdb;MODE=PostgreSQL                                                                                                                                     |
| SPRING_DATASOURCE_USERNAME          | The username to access the database                                              | sa                                                                                                                                                                     |
| SPRING_DATASOURCE_PASSWORD          | The password to access the database                                              |                                                                                                                                                                        |
| SPRING_DATASOURCE_DRIVER_CLASS_NAME | The driver used for the database                                                 | org.h2.Driver                                                                                                                                                          |
| DID_DOCUMENT_CONTEXT_URLS           | Did document context URLs                                                        | https://www.w3.org/ns/did/v1, https://w3id.org/security/suites/jws-2020/v1, https://w3id.org/dspace-dcp/v1.0/dcp.jsonld, https://w3id.org/dspace/2025/1/context.jsonld |
| ISSUER_METADATA_CONTEXT_URLS        | Issuer metadata context URLs                                                     | https://w3id.org/dspace-dcp/v1.0/dcp.jsonld, https://www.w3.org/2018/credentials/v1, https://w3id.org/catenax/credentials/v1.0.0                                       |


2. Run application using Gradle:

`./gradlew :runtimes:ssi-dim-wallet-stub:clean :runtimes:ssi-dim-wallet-stub:bootrun`

3. After successful running of the application, you can access swagger
   on  ``http://localhost:8080/ui/swagger-ui/index.html``

##### Deploy application using helm chart

Please refer [deploy using helm](charts/ssi-dim-wallet-stub/README.md)

### Documentation

Detailed documentation can be found [here](docs%2FREADME.md)

### Important notes and limitation of application

1. There are two possible options, each defined in a separate runtimes: `ssi-dim-wallet-stub` (with optional
   persistence) and `ssi-dim-wallet-stub-memory` (in-memory only).
    1. Simple Java ``Map`` is used to store keypair, VC and VP of wallet to avoid any further complexity. Please
       refer [MemoryStorage.java](src%2Fmain%2Fjava%2Forg%2Feclipse%2Ftractusx%2Fwallet%2Fstub%2Fstorage%2FMemoryStorage.java)
    2. Stored in the
       database: [DatabaseStorage.java](src%2Fmain%2Fjava%2Forg%2Feclipse%2Ftractusx%2Fwallet%2Fstub%2Fstorage%2FDatabaseStorage.java)
2. This application will create same key for given BPN on given environment. Please
   refer [DeterministicECKeyPairGenerator.java](src%2Fmain%2Fjava%2Forg%2Feclipse%2Ftractusx%2Fwallet%2Fstub%2Futils%2FDeterministicECKeyPairGenerator.java)
3. If a wallet is not created at any point of request, application will create a new wallet at runtime
4. Application will issue new VC during ``/presentations/query`` API if not issued previously
5. Application will not give error if request VC is not already issue
6. There is no separate IDP for this wallet application. OAuth token creation API is part of this application only
7. We are not validating ``client_secret`` while creating OAuth token and  ``client_id`` will be BPN
8. Negative scenarios are not covered
9. ``jti`` claim is not validated
10. No actual revocation of verifiable credentials
11. All stored credentials will be lost upon application restart unless persistence and the database are enabled.
12. JWTs are printed with debug log level for debugging purposes
13. In the DCP credential request API, the credential expiration date will be ignored as we are issuing the credentials with a fixed expiration date of 1 year.
14. In the DCP credential request API, issuerDid will be ignored as we are issuing the credentials with a fixed issuerDid of the base wallet BPN.
15. In the DCP credential request API, We can request only one credential at a time, as the application is not designed to handle multiple credentials in a single request.

### Notice for Docker image

This application provides container images for demonstration purposes.

See Docker notice files for more information:

- [SSI DIM Wallet stub Docker notice](DOCKER_NOTICE.md)

## License

Distributed under the Apache 2.0 License.
See [LICENSE](./LICENSE) for more information.
