/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 LKS Next
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

/**
 * The type Portal api doc.
 */
public class PortalApiDoc {


    /**
     * The interface Create new wallet.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Create a new wallet with BPN and send the Did document back to portal backend. Everytime same wallet generated with bpn so same did document will be generated for a wallet.
            """, summary = "Create a new wallet")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Created"),
            @ApiResponse(responseCode = "500", description = "Internal Server Error", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Internal Error Exception", value = """
                                            {
                                              "type": "about:blank",
                                              "title": "Internal Server Error",
                                              "status": 500,
                                              "detail": "InternalErrorException: **",
                                              "instance": "/api/dim/setup-dim",
                                              "properties": {
                                                "timestamp": 1743160775200
                                              }
                                            }
                                    """)
                    })
            })
    })
    public @interface CreateNewWallet {

    }

    /**
     * The interface Create new tech user.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Send clientId as BPN, clientSecret and OAuth  back to portal backend.
            """, summary = "Creates a technical user for the wallet of the given bpn.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Ok"),
            @ApiResponse(responseCode = "500", description = "Internal Server Error", content = {
                    @Content(examples = {
                            @ExampleObject(name = "Internal Error Exception", value = """
                                            {
                                              "type": "about:blank",
                                              "title": "Internal Server Error",
                                              "status": 500,
                                              "detail": "InternalErrorException: Internal Error: **",
                                              "instance": "/api/dim/technical-user/BPNL2313",
                                              "properties": {
                                                "timestamp": 1743160775200
                                              }
                                            }
                                    """)
                    })
            })
    })
    public @interface CreateNewTechUser {

    }
}
