/*
 *   *******************************************************************************
 *    Copyright (c) 2025 Cofinity-X
 *    Copyright (c) 2025 LKS Next
 *    Copyright (c) 2025 Contributors to the Eclipse Foundation
 *
 *    See the NOTICE file(s) distributed with this work for additional
 *    information regarding copyright ownership.
 *
 *    This program and the accompanying materials are made available under the
 *    terms of the Apache License, Version 2.0 which is available at
 *    https://www.apache.org/licenses/LICENSE-2.0.
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *   ******************************************************************************
 *
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

public class BDRSApiDoc {

    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Get BPN Did entries
            """, summary = "Get BPN Did entries")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "BPN DID mapping", content = {
                    @Content(examples = {
                            @ExampleObject(name = "DID document", value = """
                                    {
                                        "BPNL000000000000": "did:web:some.host.name:BPNL000000000000"
                                    }
                                    """)
                    })
            }),
            @ApiResponse(responseCode = "400", description = "Illegal Argument", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Illegal Argument Exception", value = """
                                    {
                                      "type": "about:blank",
                                      "title": "Bad request: Invalid token -> Bearer token",
                                      "status": 400,
                                      "detail": "IllegalArgumentException: Invalid token -> Bearer token",
                                      "instance": "/api/v1/directory/bpn-directory",
                                      "properties": {
                                        "timestamp": 1743084920633
                                      }
                                    }
                                    """),
                            @ExampleObject(name = "Parse Stub Exception", value = """
                                    {
                                      "type": "about:blank",
                                      "title": "Invalid serialized unsecured/JWS/JWE object: Missing part delimiters",
                                      "status": 400,
                                      "detail": "ParseStubException: Invalid serialized unsecured/JWS/JWE object: Missing part delimiters",
                                      "instance": "/api/v1/directory/bpn-directory",
                                      "properties": {
                                        "timestamp": 1743084809964
                                      }
                                    }
                                    """)
                    })
            }),
            @ApiResponse(responseCode = "401", description = "Unauthorized", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Missing Request Header Exception", value = """
                                    {
                                      "type": "about:blank",
                                      "title": "Please provide the required header: Authorization",
                                      "status": 401,
                                      "detail": "MissingRequestHeaderException: Required request header 'Authorization' for method parameter type String is not present",
                                      "instance": "/api/v1/directory/bpn-directory",
                                      "properties": {
                                        "timestamp": 1743062000750
                                      }
                                    }
                                    """)
                    })
            }),
            @ApiResponse(responseCode = "422", description = "VP Validation Failed", content = {
                    @Content(examples = {
                            @ExampleObject(name = "VP Validation Failed Exception", value = """
                                    {
                                      "type": "about:blank",
                                      "title": "Invalid Verifiable Presentation",
                                      "status": 422,
                                      "detail": "VPValidationFailedException: Invalid VP token: e...",
                                      "instance": "/api/v1/directory/bpn-directory",
                                      "properties": {
                                        "timestamp": 1743062000750
                                      }
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
                                      "instance": "/api/v1/directory/bpn-directory",
                                      "properties": {
                                        "timestamp": 1743062000750
                                      }
                                    }
                                    """)
                    })
            })
    })
    public @interface BDRSDirectory {

    }
}
