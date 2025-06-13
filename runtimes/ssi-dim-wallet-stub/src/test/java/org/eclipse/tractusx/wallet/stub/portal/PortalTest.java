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

package org.eclipse.tractusx.wallet.stub.portal;

import lombok.SneakyThrows;
import org.eclipse.tractusx.wallet.stub.runtime.postgresql.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.CreateTechUserRequest;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = { WalletStubApplication.class })
@ContextConfiguration(initializers = { TestContextInitializer.class })
class PortalTest {
    @Autowired
    private TestRestTemplate restTemplate;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private TokenSettings tokenSettings;
    @Autowired
    private WalletStubSettings walletStubSettings;


    @SneakyThrows
    @Test
    @DisplayName("Test Create Wallet")
    void testCreateWallet() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        String holderBpn = TestUtils.getRandomBpmNumber();
        String didLocation = walletStubSettings.stubUrl() + "/" + holderBpn + "/did.json";

        HttpEntity entity = new HttpEntity<>(headers);
        // Query parameters
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString("/api/dim/setup-dim")
                // Add query parameter
                .queryParam("bpn", holderBpn)
                .queryParam("companyName", "Abc")
                .queryParam("didDocumentLocation", didLocation);
        ResponseEntity<Void> response = restTemplate.exchange(builder.toUriString(), HttpMethod.POST, entity, Void.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.CREATED.value());
    }


    @SneakyThrows
    @Test
    @DisplayName("Test Create Tech User")
    void testCreateTechUser() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));
        String holderBpn = TestUtils.getRandomBpmNumber();
        CreateTechUserRequest createTechUserRequest = CreateTechUserRequest.builder().name("Abc").externalId("uuid").build();
        HttpEntity<CreateTechUserRequest> entity = new HttpEntity<>(createTechUserRequest, headers);

        ResponseEntity<Void> response = restTemplate.exchange("/api/dim/technical-user/{bpn}", HttpMethod.POST, entity, Void.class, holderBpn, holderBpn);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
    }
}
