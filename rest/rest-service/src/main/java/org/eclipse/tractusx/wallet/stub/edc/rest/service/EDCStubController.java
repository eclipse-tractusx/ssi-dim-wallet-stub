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

package org.eclipse.tractusx.wallet.stub.edc.rest.service;


import io.swagger.v3.oas.annotations.Parameter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.eclipse.tractusx.wallet.stub.edc.api.EDCStubService;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.QueryPresentationResponse;
import org.eclipse.tractusx.wallet.stub.edc.api.dto.StsTokeResponse;
import org.eclipse.tractusx.wallet.stub.edc.rest.api.EDCStubApi;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@RestController
public class EDCStubController implements EDCStubApi {

    private final EDCStubService edcStubService;

    @Override
    public ResponseEntity<StsTokeResponse> createTokenWithScope(
            @RequestBody Map<String, Object> request,
            @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token
    ) {
        return ResponseEntity.ok(StsTokeResponse.builder().jwt(edcStubService.createStsToken(request, token)).build());
    }

    @Override
    public ResponseEntity<QueryPresentationResponse> queryPresentations(
            @RequestBody QueryPresentationRequest request,
            @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION) String token
    ) {
        return ResponseEntity.ok(edcStubService.queryPresentations(request, token));
    }
}
