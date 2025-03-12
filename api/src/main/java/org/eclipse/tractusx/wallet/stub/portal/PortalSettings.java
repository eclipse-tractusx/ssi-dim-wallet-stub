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

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Setting class configuration properties related to portal backend
 *
 * @param portalWaitTime The number of seconds to wait before pushing data to portal backend
 * @param clientId       The client id of portal
 * @param clientSecret   The client secret of portal
 * @param realm          The keycloak of the realm
 * @param authServerUrl  The auth server url
 */
@ConfigurationProperties(prefix = "stub.portal")
public record PortalSettings(long portalWaitTime, String clientId, String clientSecret, String realm,
                             String authServerUrl) {
}
