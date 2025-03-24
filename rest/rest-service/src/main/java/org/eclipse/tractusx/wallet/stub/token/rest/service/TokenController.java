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

package org.eclipse.tractusx.wallet.stub.token.rest.service;


import io.swagger.v3.oas.annotations.Parameter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenRequest;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenResponse;
import org.eclipse.tractusx.wallet.stub.token.rest.api.TokenApi;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequiredArgsConstructor
public class TokenController implements TokenApi {

    private final TokenService tokenService;

    @Override
    public ResponseEntity<TokenResponse> createAccessToken(@ModelAttribute @RequestBody TokenRequest request, @Parameter(hidden = true) @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String token) {
        setClientInfo(request, token);
        return ResponseEntity.ok(tokenService.createAccessTokenResponse(request));
    }

    @SneakyThrows
    private void setClientInfo(TokenRequest request, String token) {
        if (StringUtils.isNoneBlank(token)) {
            String[] split = token.split(StringUtils.SPACE);
            if (split.length == 2 && split[0].equals(Constants.BASIC)) {
                String encodedString = split[1];
                // Decode the Base64 encoded string
                byte[] decodedBytes = Base64.getDecoder().decode(encodedString);
                String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);

                // Split the decoded string by colon to get clientId and clientSecret
                String[] parts = decodedString.split(":");
                if (parts.length == 2) {
                    request.setClientId(parts[0]);
                    request.setClientSecret(parts[1]);
                } else {
                    throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Authorization header invalid");
                }
            } else {
                throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Authorization header invalid");
            }
        }
    }
}
