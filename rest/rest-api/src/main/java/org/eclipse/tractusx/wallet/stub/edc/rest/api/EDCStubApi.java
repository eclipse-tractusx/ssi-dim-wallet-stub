/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
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

package org.eclipse.tractusx.wallet.stub.edc.rest.api;


import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.eclipse.tractusx.wallet.stub.apidoc.rest.api.EDCStubApiDoc;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationResponse;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.StsTokeResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import java.util.Map;

@Tag(name = "APIs consumed by EDC")
public interface EDCStubApi {

    /**
     * This method is responsible for creating a JWT token with a specific scope.
     *
     * @param request The request object containing the necessary data to create the token.
     * @param token   The authorization token provided in the request header.
     * @return A ResponseEntity containing a map with a single key-value pair: "jwt" and the generated JWT token.
     */
    @EDCStubApiDoc.GetSts
    @PostMapping(path = "/api/sts", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<StsTokeResponse> createTokenWithScope(@RequestBody Map<String, Object> request,
                                                         @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token);


    /**
     * This method is responsible for querying presentations based on the provided request.
     *
     * @param request The request object containing the necessary data for querying presentations.
     * @param token   The authorization token provided in the request header.
     * @return A ResponseEntity containing the QueryPresentationResponse object with the query results.
     */
    @EDCStubApiDoc.QueryPresentation
    @PostMapping(path = "/api/presentations/query")
    ResponseEntity<QueryPresentationResponse> queryPresentations(@RequestBody QueryPresentationRequest request,
                                                                 @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token);
}
