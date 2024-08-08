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

package org.eclipse.tractusx.wallet.stub.portal;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.net.ServerSocket;


class KeycloakServiceTest {


    private final KeycloakService keycloakService;

    private final int port = findFreePort();

    WireMockServer wireMockServer;


    KeycloakServiceTest() {
        PortalSettings portalSettings = new PortalSettings(1, "clientId", "clientSecret", "realm", "http://localhost:" + port);
        keycloakService = new KeycloakService(portalSettings);
    }

    @SneakyThrows
    private static int findFreePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @BeforeEach
    void setUp() {
        wireMockServer = new WireMockServer(port);
        wireMockServer.start();
        setupStub();
    }

    public void setupStub() {
        wireMockServer.stubFor(WireMock.post("/realms/realm/protocol/openid-connect/token")
                .willReturn(WireMock.aResponse()
                        .withStatus(HttpStatus.OK.value())
                        .withBody("{\"access_token\":\"access_token\",\"token_type\":\"bearer\",\"expires_in\":3600,\"refresh_expires_in\":1800,\"refresh_token\":\"refresh_token\",\"id_token\":\"id_token\",\"not_before_policy\":0,\"session_state\":\"session_state\",\"scope\":\"openid profile email offline_access\",\"acr\":\"0\"}")
                        .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)));
    }

    @AfterEach
    void afterEach() {
        wireMockServer.shutdown();
    }

    @Test
    void testCreateAccessToken() {
        String portalAccessToken = keycloakService.createPortalAccessToken();
        Assertions.assertEquals("bearer access_token", portalAccessToken);
    }
}
