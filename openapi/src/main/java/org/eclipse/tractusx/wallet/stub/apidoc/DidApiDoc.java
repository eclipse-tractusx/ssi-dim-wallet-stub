/*
 * *******************************************************************************
 *  Copyright (c) 2024 Contributors to the Eclipse Foundation
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
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


/**
 * The type Did api doc.
 */
public class DidApiDoc {


    /**
     * The interface Did document.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Resolve the DID document for a given BPN

            """, summary = "Resolve the DID document for a given BPN")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "DID document", content = {
                    @Content(examples = {
                            @ExampleObject(name = "DID document", value = """
                                    {
                                      "service": [
                                        {
                                          "id": "https://localhost#credential-service",
                                          "type": "CredentialService",
                                          "serviceEndpoint": "https://localhost/api"
                                        }
                                      ],
                                      "verificationMethod": [
                                        {
                                          "id": "did:web:localhost:BPNL000000000000#c3932ff5-8da4-3de9-a942-62125f394e41",
                                          "type": "JsonWebKey2020",
                                          "controller": "did:web:localhost:BPNL000000000000",
                                          "publicKeyJwk": {
                                            "kty": "EC",
                                            "use": "sig",
                                            "crv": "secp256k1",
                                            "x": "NytYgtL_rte4EIXpb46e7pntJiPjH4l_pN1j1PVxkO8",
                                            "y": "99JkYiCOkBfb8qCncv_YWdHy3eZGAQojWbmaEDFwSlU"
                                          }
                                        }
                                      ],
                                      "authentication": [
                                        "did:web:localhost:BPNL000000000000#c3932ff5-8da4-3de9-a942-62125f394e41"
                                      ],
                                      "id": "did:web:localhost:BPNL000000000000",
                                      "@context": [
                                        "https://www.w3.org/ns/did/v1",
                                        "https://w3c.github.io/vc-jws-2020/contexts/v1",
                                        "https://w3id.org/did-resolution/v1"
                                      ]
                                    }
                                    """)
                    })
            })
    })
    public @interface DidDocument {

    }
}
