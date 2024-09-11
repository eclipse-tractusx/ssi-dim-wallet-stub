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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.mockito.MockedStatic;
import org.mockito.Mockito;


class KeycloakServiceTest {


    private final KeycloakService keycloakService;

    private final PortalSettings portalSettings;

    KeycloakServiceTest() {
        portalSettings = Mockito.mock();
        keycloakService = new KeycloakService(portalSettings);
    }

    @BeforeEach
    void setUp() {

        setupStub();
    }

    public void setupStub() {

    }

    @AfterEach
    void afterEach() {
    }


    @Test
    void shouldReturnValidAccessTokenWhenAllRequiredSettingsAreProvided() {
        try (MockedStatic<KeycloakBuilder> mockerBuilder = Mockito.mockStatic(KeycloakBuilder.class)) {
            KeycloakBuilder keycloakBuilder = Mockito.mock(KeycloakBuilder.class);
            Keycloak keycloak = Mockito.mock(Keycloak.class);
            TokenManager tokenManager = Mockito.mock(TokenManager.class);
            AccessTokenResponse accessTokenResponse = Mockito.mock(AccessTokenResponse.class);

            //mock portal
            Mockito.when(portalSettings.clientId()).thenReturn("client_id");
            Mockito.when(portalSettings.clientSecret()).thenReturn("client_secret");
            Mockito.when(portalSettings.realm()).thenReturn("realm");
            Mockito.when(portalSettings.authServerUrl()).thenReturn("http://localhost");

            //mock builder
            mockerBuilder.when(KeycloakBuilder::builder).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.realm(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.clientId(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.clientSecret(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.grantType(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.serverUrl(Mockito.anyString())).thenReturn(keycloakBuilder);
            Mockito.when(keycloakBuilder.build()).thenReturn(keycloak);
            Mockito.when(keycloak.tokenManager()).thenReturn(tokenManager);
            Mockito.when(tokenManager.getAccessToken()).thenReturn(accessTokenResponse);

            Mockito.when(accessTokenResponse.getToken()).thenReturn("access_token");
            Mockito.when(accessTokenResponse.getTokenType()).thenReturn("type");
            String portalAccessToken = keycloakService.createPortalAccessToken();
            Assertions.assertEquals("type access_token", portalAccessToken);
        }
    }
}
