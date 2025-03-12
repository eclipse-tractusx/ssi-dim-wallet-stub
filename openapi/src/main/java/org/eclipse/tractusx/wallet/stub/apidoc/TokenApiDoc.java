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
 * The type Token api doc.
 */
public class TokenApiDoc {


    /**
     * The interface Create idp token.
     */
    @Target(ElementType.METHOD)
    @Retention(RetentionPolicy.RUNTIME)
    @Operation(description = """
            Create OAuth token to access wallet APIs
            """, summary = "Create OAuth token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "JWT presentation", content = {
                    @Content(examples = {
                            @ExampleObject(name = "IDP token to access wallet API", value = """
                                    {
                                          "access_token": "eyJraWQiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAjYzM5MzJmZjUtOGRhNC0zZGU5LWE5NDItNjIxMjVmMzk0ZTQxIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJhdWQiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAiLCJicG4iOiJCUE5MMDAwMDAwMDAwMDAwIiwic3ViIjoiZGlkOndlYjpjNDY0LTIwMy0xMjktMjEzLTEwNy5uZ3Jvay1mcmVlLmFwcDpCUE5MMDAwMDAwMDAwMDAwIiwibmJmIjoxNzE5NDgxNjYxLCJpc3MiOiJkaWQ6d2ViOmM0NjQtMjAzLTEyOS0yMTMtMTA3Lm5ncm9rLWZyZWUuYXBwOkJQTkwwMDAwMDAwMDAwMDAiLCJleHAiOjE3MTk0ODE5NjEsImlhdCI6MTcxOTQ4MTY2MSwianRpIjoiOWUxOTYzOGUtZDVmZi00NWMyLWI5MTktZDJmMGE1YTg0ODRlIn0.Ap96JWRJga-CEIE6p85TKy6u3X1b21z87rXJRhD5K2lNgADjxyJk967vvW5jf6_avQEyg8sEPN37rtarT4ayTw",
                                          "token_type": "Bearer",
                                          "expires_in": 300,
                                          "refresh_expires_in": 0,
                                          "not-before-policy": 0,
                                          "scope": "email profile"
                                      }
                                    """)
                    })
            })
    })
    public @interface CreateIdpToken {

    }
}
