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

package org.eclipse.tractusx.wallet.stub.oauth;

import lombok.SneakyThrows;
import org.eclipse.tractusx.wallet.stub.runtime.postgresql.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.token.api.dto.TokenResponse;
import org.eclipse.tractusx.wallet.stub.utils.test.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Base64;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = { WalletStubApplication.class })
@ContextConfiguration(initializers = { TestContextInitializer.class })
class OauthTokenTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TokenSettings tokenSettings;

    @Autowired
    private TokenService tokenService;

    @SneakyThrows
    @Test
    @DisplayName("Create Oauth token with Basic Authentication")
    void createAuthTokenWithBasicCredential() {
        String bpn = TestUtils.getRandomBpmNumber();
        String pass = bpn + ":" + bpn;
        String auth = "Basic " + new String(Base64.getEncoder().encode(pass.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.AUTHORIZATION, auth);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();

        HttpEntity<MultiValueMap<String, String>> formEntity = new HttpEntity<>(requestBody, headers);
        ResponseEntity<TokenResponse> response = restTemplate.exchange("/oauth/token", HttpMethod.POST, formEntity, TokenResponse.class);
        TestUtils.verifyTokenResponse(response, bpn, tokenService, tokenSettings);

    }

    @SneakyThrows
    @Test
    @DisplayName("Create Oauth token and verify bpn claim")
    void createAuthToken() {
        String bpn = TestUtils.getRandomBpmNumber();
        String aOauthToken = TestUtils.createAOauthToken(bpn, restTemplate, tokenService, tokenSettings);
        Assertions.assertNotNull(aOauthToken);
    }
}
