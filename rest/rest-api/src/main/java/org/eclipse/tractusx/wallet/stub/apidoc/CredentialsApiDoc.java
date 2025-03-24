/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0.
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.wallet.stub.apidoc;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This class contains API documentations for various methods related to credentials.
 */
public class CredentialsApiDoc {


    /**
     * The interface Create store credential.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            New credential sign with issuer wallet and saved in in-memory db and send VC id in the response. | Store credential will give only static response with id.
            """, summary = "Create a new credential | Store credential for a holder")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "JWT presentation", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Create a new credential", value = """
                                    {
                                       "id": "1f36af58-0fc0-4b24-9b1c-e37d59668089"
                                    }
                                    """),
                            @ExampleObject(name = "Create a new credential with signature", value = """
                                    {
                                       "id": "1f36af58-0fc0-4b24-9b1c-e37d59668089",
                                       "jwt":"eyJraWQiOiJkaWQ6d2ViOnNvbWUtaXNzdWVyI2tleS0xIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkZWdyZWVTdWIiLCJhdWQiOiJkaWQ6d2ViOmJkcnMtY2xpZW50IiwibmJmIjoxNzE4MzQzOTAzLCJpc3MiOiJkaWQ6d2ViOnNvbWUtaXNzdWVyIiwiZXhwIjoxNzE4MzQzOTYzLCJpYXQiOjE3MTgzNDM5MDMsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9jYXRlbmF4L2NyZWRlbnRpYWxzL3YxLjAuMCJdLCJpZCI6IjFmMzZhZjU4LTBmYzAtNGIyNC05YjFjLWUzN2Q1OTY2ODA4OSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJNZW1iZXJzaGlwQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6d2ViOmNvbS5leGFtcGxlLmlzc3VlciIsImlzc3VhbmNlRGF0ZSI6IjIwMjEtMDYtMTZUMTg6NTY6NTlaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDk5LTA2LTE2VDE4OjU2OjU5WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOndlYjpiZHJzLWNsaWVudCIsImhvbGRlcklkZW50aWZpZXIiOiJCUE5MMDAwMDAwMDAxIn19LCJqdGkiOiJlZDlhNjhkMS0yZjFkLTQxZjgtYWUwOS1hNDBhMTA2OTUwMTUifQ.tdLmrcQpGH-SGBpRpRmFX4AXQJx99uUhDOwuGtSejWkkQ2N_yNtEsoP93xDuBod_AY7zVqY4P_Ofdz-H4zE6nw"
                                    }
                                    """),
                            @ExampleObject(name = "Store credential for a holder", value = """
                                    {
                                       "id": "1f36af58-0fc0-4b24-9b1c-e37d59668089"
                                    }
                                    """)
                    })
            })
    })
    @RequestBody(content = {
            @Content(examples = {
                    @ExampleObject(value = """
                            {
                                 "application": "catena-x",
                                 "payload":
                                 {
                                     "issueWithSignature":
                                     {
                                         "content":
                                         {
                                             "@context":
                                             [
                                                 "https://www.w3.org/2018/credentials/v1",
                                                 "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                                 "https://w3id.org/security/suites/jws-2020/v1"
                                             ],
                                             "id": "did:web:localhost:BPNL000000000000#a1f8ae36-9919-4ed8-8546-535280acc5bf",
                                             "type":
                                             [
                                                 "VerifiableCredential",
                                                 "BpnCredential"
                                             ],
                                             "issuer": "did:web:localhost:BPNL000000000000",
                                             "issuanceDate": "2023-07-19T09:14:45Z",
                                             "expirationDate": "2023-09-30T18:30:00Z",
                                             "credentialSubject":
                                             {
                                                 "bpn": "BPNL000000000001",
                                                 "id": "did:web:localhost:BPNL000000000001",
                                                 "type": "BpnCredential"
                                             }
                                         },
                                         "signature": {
                                                 "proofMechanism": "external",
                                                 "proofType": "jwt",
                                                 "keyName": null
                                         }
                                     }
                                 }
                             }
                            """, description = "Create a new credential with signature", name = "Create a new credential with signature"),
                    @ExampleObject(value = """
                            {
                              "application": "catena-x",
                              "payload": {
                                "issue": {
                                  "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                    "https://w3id.org/security/suites/jws-2020/v1"
                                  ],
                                  "id": "did:web:localhost:BPNL000000000000#a1f8ae36-9919-4ed8-8546-535280acc5bf",
                                  "type": [
                                    "VerifiableCredential",
                                    "BpnCredential"
                                  ],
                                  "issuer": "did:web:localhost:BPNL000000000000",
                                  "issuanceDate": "2023-07-19T09:14:45Z",
                                  "expirationDate": "2023-09-30T18:30:00Z",
                                  "credentialSubject": {
                                      "bpn": "BPNL000000000001",
                                      "id": "did:web:localhost:BPNL000000000001",
                                      "type": "BpnCredential"
                                  }
                                }
                              }
                            }
                            """, description = "Create a new credential", name = "Create a new credential"),
                    @ExampleObject(value = """
                            {
                              "application": "catena-x-portal",
                              "payload": {
                                "derive": {
                                  "verifiableCredential": "eyJraWQiOiJkaWQ6d2ViOnNvbWUtaXNzdWVyI2tleS0xIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkZWdyZWVTdWIiLCJhdWQiOiJkaWQ6d2ViOmJkcnMtY2xpZW50IiwibmJmIjoxNzE4MzQzOTAzLCJpc3MiOiJkaWQ6d2ViOnNvbWUtaXNzdWVyIiwiZXhwIjoxNzE4MzQzOTYzLCJpYXQiOjE3MTgzNDM5MDMsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9jYXRlbmF4L2NyZWRlbnRpYWxzL3YxLjAuMCJdLCJpZCI6IjFmMzZhZjU4LTBmYzAtNGIyNC05YjFjLWUzN2Q1OTY2ODA4OSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJNZW1iZXJzaGlwQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6d2ViOmNvbS5leGFtcGxlLmlzc3VlciIsImlzc3VhbmNlRGF0ZSI6IjIwMjEtMDYtMTZUMTg6NTY6NTlaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDk5LTA2LTE2VDE4OjU2OjU5WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOndlYjpiZHJzLWNsaWVudCIsImhvbGRlcklkZW50aWZpZXIiOiJCUE5MMDAwMDAwMDAxIn19LCJqdGkiOiJlZDlhNjhkMS0yZjFkLTQxZjgtYWUwOS1hNDBhMTA2OTUwMTUifQ.tdLmrcQpGH-SGBpRpRmFX4AXQJx99uUhDOwuGtSejWkkQ2N_yNtEsoP93xDuBod_AY7zVqY4P_Ofdz-H4zE6nw"
                                }
                              }
                            }
                            """, description = "Store credential for a holder", name = "Store credential for a holder")

            })
    })
    public @interface CreateStoreCredential {

    }

    /**
     * The interface Sign revoke credential.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Credential already signed now it will send vc in response. | Revoke a credential will give static response.
            """, summary = "Sign a credential / Revoke a credential")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "JWT presentation", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Sign credential", value = """
                                    {
                                      "jwt": "eyJraWQiOiJkaWQ6d2ViOnNvbWUtaXNzdWVyI2tleS0xIiwiYWxnIjoiRVMyNTYifQ.eyJzdWIiOiJkZWdyZWVTdWIiLCJhdWQiOiJkaWQ6d2ViOmJkcnMtY2xpZW50IiwibmJmIjoxNzE4MzQzOTAzLCJpc3MiOiJkaWQ6d2ViOnNvbWUtaXNzdWVyIiwiZXhwIjoxNzE4MzQzOTYzLCJpYXQiOjE3MTgzNDM5MDMsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly93M2lkLm9yZy9jYXRlbmF4L2NyZWRlbnRpYWxzL3YxLjAuMCJdLCJpZCI6IjFmMzZhZjU4LTBmYzAtNGIyNC05YjFjLWUzN2Q1OTY2ODA4OSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJNZW1iZXJzaGlwQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6d2ViOmNvbS5leGFtcGxlLmlzc3VlciIsImlzc3VhbmNlRGF0ZSI6IjIwMjEtMDYtMTZUMTg6NTY6NTlaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDk5LTA2LTE2VDE4OjU2OjU5WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOndlYjpiZHJzLWNsaWVudCIsImhvbGRlcklkZW50aWZpZXIiOiJCUE5MMDAwMDAwMDAxIn19LCJqdGkiOiJlZDlhNjhkMS0yZjFkLTQxZjgtYWUwOS1hNDBhMTA2OTUwMTUifQ.tdLmrcQpGH-SGBpRpRmFX4AXQJx99uUhDOwuGtSejWkkQ2N_yNtEsoP93xDuBod_AY7zVqY4P_Ofdz-H4zE6nw"
                                    }
                                    """),
                            @ExampleObject(name = "Revoke credential ", value = """
                                    {
                                    }
                                    """)
                    })
            })
    })
    @RequestBody(content = {
            @Content(examples = {
                    @ExampleObject(value = """
                            {
                              "sign": {
                                "proofMechanism": "external",
                                "proofType": "jwt"
                              }
                            }
                            """, description = "Sign credential", name = "Sign credential"),
                    @ExampleObject(value = """
                            {
                              "payload": {
                                "revoke": true
                              }
                            }
                            """, description = "Revoke credential", name = "Revoke credential")

            })
    })
    public @interface SignRevokeCredential {

    }

    /**
     * The interface Get credentials.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Get a credential by external ID. It will work if vc is present in in-memory db.
            """, summary = "Get a credential by external ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Get credential", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Get credential", value = """
                                    {
                                      "verifiableCredential": "eyJraWQiOiJkaWQ6d2ViOmxvY2FsaG9zdDpCUE5MMDAwMDAwMDAwMDAwI2MzOTMyZmY1LThkYTQtM2RlOS1hOTQyLTYyMTI1ZjM5NGU0MSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJhdWQiOlsiZGlkOndlYjpsb2NhbGhvc3Q6QlBOTDAwMDAwMDAwMDAwMCIsImRpZDp3ZWI6bG9jYWxob3N0OkJQTkwwMDAwMDAwMDAwMDEiXSwiYnBuIjoiQlBOTDAwMDAwMDAwMDAwMSIsInN1YiI6ImRpZDp3ZWI6bG9jYWxob3N0OkJQTkwwMDAwMDAwMDAwMDAiLCJpc3MiOiJkaWQ6d2ViOmxvY2FsaG9zdDpCUE5MMDAwMDAwMDAwMDAwIiwiZXhwIjoxNzE5ODA5NTQ1LCJpYXQiOjE3MTk4MDkyNDUsInZjIjp7Imlzc3VhbmNlRGF0ZSI6IjIwMjMtMDctMTlUMDk6MTQ6NDVaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiYnBuIjoiQlBOTDAwMDAwMDAwMDAwMSIsImlkIjoiZGlkOndlYjpsb2NhbGhvc3Q6QlBOTDAwMDAwMDAwMDAwMSIsInR5cGUiOiJCcG5DcmVkZW50aWFsIn0sImlkIjoiZGlkOndlYjpsb2NhbGhvc3Q6QlBOTDAwMDAwMDAwMDAwMCMxOWNiNjU2Mi1iYWM3LTNkYzMtYWFmNi00NjEyZTM0OWEwMTEiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiQnBuQ3JlZGVudGlhbCJdLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vY2F0ZW5heC1uZy5naXRodWIuaW8vcHJvZHVjdC1jb3JlLXNjaGVtYXMvYnVzaW5lc3NQYXJ0bmVyRGF0YS5qc29uIiwiaHR0cHM6Ly93M2lkLm9yZy9zZWN1cml0eS9zdWl0ZXMvandzLTIwMjAvdjEiXSwiaXNzdWVyIjoiZGlkOndlYjpsb2NhbGhvc3Q6QlBOTDAwMDAwMDAwMDAwMCIsImV4cGlyYXRpb25EYXRlIjoiMjAyMy0wOS0zMFQxODozMDowMFoifSwianRpIjoiYjcyMWY0NjMtMzM3Yi00MzBhLTkzMDktNjZlNzBjMjNkNTZiIn0._mGVXN4ublBx0-r0lG7_2tSGzwIlhjTWtx-ZFcQMmg4Q9pvF-RnbSDZ0vJLfvWv9egVtFSPE9oqbChCLXVg21g",
                                      "credential": {
                                        "issuanceDate": "2023-07-19T09:14:45Z",
                                        "credentialSubject": {
                                          "bpn": "BPNL000000000001",
                                          "id": "did:web:localhost:BPNL000000000001",
                                          "type": "BpnCredential"
                                        },
                                        "id": "did:web:localhost:BPNL000000000000#19cb6562-bac7-3dc3-aaf6-4612e349a011",
                                        "type": [
                                          "VerifiableCredential",
                                          "BpnCredential"
                                        ],
                                        "@context": [
                                          "https://www.w3.org/2018/credentials/v1",
                                          "https://catenax-ng.github.io/product-core-schemas/businessPartnerData.json",
                                          "https://w3id.org/security/suites/jws-2020/v1"
                                        ],
                                        "issuer": "did:web:localhost:BPNL000000000000",
                                        "expirationDate": "2023-09-30T18:30:00Z"
                                      },
                                      "revocationStatus": "false",
                                      "signing_key_id": "did:web:localhost:BPNL000000000000#c3932ff5-8da4-3de9-a942-62125f394e41"
                                    }
                                    """)
                    })
            })
    })
    public @interface GetCredentials {

    }
}
