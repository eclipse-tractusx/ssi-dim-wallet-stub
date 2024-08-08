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


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.stereotype.Service;

/**
 * This class provides method to interact with keycloak(IDP)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class KeycloakService {


    public static final String CLIENT_CREDENTIALS = "client_credentials";
    private final PortalSettings portalSettings;


    /**
     * This method creates a portal access token using Keycloak's client credentials grant type.
     * The access token is used to authenticate requests to the portal's backend services.
     *
     * @return A string representing the portal access token in the format: "Bearer <access_token>".
     */
    public String createPortalAccessToken() {
        try (Keycloak keycloak = KeycloakBuilder.builder()
                .clientId(portalSettings.clientId())
                .clientSecret(portalSettings.clientSecret())
                .grantType(CLIENT_CREDENTIALS)
                .realm(portalSettings.realm())
                .serverUrl(portalSettings.authServerUrl())
                .build()) {
            AccessTokenResponse accessToken = keycloak.tokenManager().getAccessToken();
            return accessToken.getTokenType() + StringUtils.SPACE + accessToken.getToken();
        }
    }
}
