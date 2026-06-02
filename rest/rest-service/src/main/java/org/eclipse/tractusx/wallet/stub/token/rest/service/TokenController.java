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

package org.eclipse.tractusx.wallet.stub.token.rest.service;


import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenResponse;
import org.eclipse.tractusx.wallet.stub.token.rest.api.TokenApi;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class TokenController implements TokenApi {

    private final TokenService tokenService;
    private final DidDocumentService didDocumentService;
    private final String didHost;

    public TokenController(TokenService tokenService,
                           DidDocumentService didDocumentService,
                           @Value("${stub.didHost}") String didHost) {
        this.tokenService = tokenService;
        this.didDocumentService = didDocumentService;
        this.didHost = didHost;
    }

    @Override
    public ResponseEntity<TokenResponse> createAccessToken(TokenRequest request, String token) {
        tokenService.setClientInfo(request, token);
        String did = CommonUtils.getDidWeb(didHost, request.getClientId());
        return ResponseEntity.ok(tokenService.createAccessTokenResponse(request, didDocumentService.getOrCreateDidDocument(did)));
    }
}
