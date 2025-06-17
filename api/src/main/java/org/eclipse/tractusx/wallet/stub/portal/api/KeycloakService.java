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

package org.eclipse.tractusx.wallet.stub.portal.api;

/**
 * This class provides method to interact with keycloak(IDP)
 */
public interface KeycloakService {


    String CLIENT_CREDENTIALS = "client_credentials";

    /**
     * This method creates a portal access token using Keycloak's client credentials grant type.
     * The access token is used to authenticate requests to the portal's backend services.
     *
     * @return A string representing the portal access token in the format: "Bearer <access_token>".
     */
    String createPortalAccessToken();
}
