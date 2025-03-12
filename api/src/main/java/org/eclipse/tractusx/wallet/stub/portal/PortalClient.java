/*
 *   *******************************************************************************
 *    Copyright (c) 2024 Cofinity-X
 *    Copyright (c) 2024 Contributors to the Eclipse Foundation
 *
 *    See the NOTICE file(s) distributed with this work for additional
 *    information regarding copyright ownership.
 *
 *    This program and the accompanying materials are made available under the
 *    terms of the Apache License, Version 2.0 which is available at
 *    https://www.apache.org/licenses/LICENSE-2.0.
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *   ******************************************************************************
 *
 */

package org.eclipse.tractusx.wallet.stub.portal;

import org.eclipse.tractusx.wallet.stub.portal.dto.AuthenticationDetails;
import org.eclipse.tractusx.wallet.stub.portal.dto.DidDocumentRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;


/**
 * This interface represents a client for interacting with the portal service.
 * It uses FeignClient to communicate with the specified URL.
 */
@FeignClient(value = "portal", url = "${stub.portal.portalHost}")
public interface PortalClient {

    /**
     * Sends a DID Document to the portal service for a specific business process node (BPN).
     *
     * @param bpn         The business process node identifier.
     * @param request     The DID Document request containing the necessary data.
     * @param accessToken The authorization token for authentication.
     * @return ResponseEntity with HTTP status code and body. In this case, the body is Void.
     */
    @PostMapping(path = "/api/administration/registration/dim/{bpn}", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<Void> sendDidDocument(@PathVariable(name = "bpn") String bpn, @RequestBody DidDocumentRequest request, @RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken);

    /**
     * Sends technical user details to the portal service for a specific business process node (BPN).
     *
     * @param bpn         The business process node identifier.
     * @param request     The technical user details request containing the necessary data.
     * @param accessToken The authorization token for authentication.
     * @return ResponseEntity with HTTP status code and body. In this case, the body is Void.
     */
    @PostMapping(path = "/api/administration/serviceAccount/callback/{externalId}", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<Void> sendTechnicalUserDetails(@PathVariable(name = "externalId") String bpn, @RequestBody AuthenticationDetails request, @RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken);
}
