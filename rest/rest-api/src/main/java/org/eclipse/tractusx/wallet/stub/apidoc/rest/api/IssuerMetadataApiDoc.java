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

package org.eclipse.tractusx.wallet.stub.apidoc.rest.api;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

public class IssuerMetadataApiDoc {


    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Get issuer metadata as per DCP issuance flow. It will return supported credentials and credential issuer
            """, summary = "Get Issuer Metadata")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Issuer metadata", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Sample issuer metadata", value = """
                                    {
                                       "@context": [
                                         "https://w3id.org/dspace-dcp/v1.0/dcp.jsonld",
                                         "https://www.w3.org/2018/credentials/v1",
                                         "https://www.w3.org/2018/credentials/examples/v1"
                                       ],
                                       "type": "IssuerMetadata",
                                       "credentialIssuer": "did:web:wallet-stub-host:BPNL000000000001",
                                       "credentialsSupported": [
                                         {
                                           "type": "CredentialObject",
                                           "profiles": [
                                             "vc20-bssl/jwt",
                                             "vc10-sl2021/jwt"
                                           ],
                                           "offerReason": "reissue",
                                           "bindingMethods": [
                                             "did:web"
                                           ],
                                           "credentialType": [
                                             "BpnCredential",
                                             "MembershipCredential"
                                           ],
                                           "issuancePolicy": {}
                                         }
                                       ]
                                     }
                                    """)
                    })
            }),

            @ApiResponse(responseCode = "500", description = "Internal Server Error", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Internal Error Exception", value = """
                                    {
                                      "type": "about:blank",
                                      "title": "Internal Server Error",
                                      "status": 500,
                                      "detail": "InternalErrorException: ...",
                                      "instance": "/api/v1.0.0/dcp/{wallet identifier}/metadata",
                                      "properties": {
                                        "timestamp": 1743062000750
                                      }
                                    }
                                    """)
                    })
            })
    })
    public @interface IssuerMetadata {

    }
}
