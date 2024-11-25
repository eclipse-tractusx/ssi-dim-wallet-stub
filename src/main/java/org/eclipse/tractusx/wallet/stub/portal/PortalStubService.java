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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.portal.dto.AuthenticationDetails;
import org.eclipse.tractusx.wallet.stub.portal.dto.CreateTechUserRequest;
import org.eclipse.tractusx.wallet.stub.portal.dto.DidDocumentRequest;
import org.eclipse.tractusx.wallet.stub.portal.dto.SetupDimRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Portal Dependencies")
public class PortalStubService {

    private final PortalClient portalClient;

    private final ObjectMapper objectMapper;

    private final PortalSettings portalSettings;

    private final WalletStubSettings walletStubSettings;

    private final DidDocumentService didDocumentService;

    private final KeycloakService keycloakService;

    /**
     * Set up DIM for a company.
     *
     * @param request The request object containing company information.
     */
    @SneakyThrows
    @Async
    public void setupDim(SetupDimRequest request) {
        log.debug("Request to setup dim received for company name -> {}, bpn ->{} waiting for 60 sec", StringEscapeUtils.escapeJava(request.getCompanyName()), StringEscapeUtils.escapeJava(request.getBpn()));

        //wait for defined time before pushing data to the portal
        Thread.sleep(portalSettings.portalWaitTime() * 1000);

        //create did a document
        DidDocument didDocument = didDocumentService.getDidDocument(request.getBpn());

        DidDocumentRequest didDocumentRequest = DidDocumentRequest.builder()
                .didDocument(didDocument)
                .did(didDocument.getId())
                .authenticationDetails(
                        AuthenticationDetails.builder()
                                .authenticationServiceUrl(walletStubSettings.stubUrl())
                                .clientId(request.getBpn())
                                .clientSecret(request.getBpn())
                                .build()
                )
                .build();

        log.debug("Did document create for bpn -> {} , didDocument - >{}", StringEscapeUtils.escapeJava(request.getBpn()), objectMapper.writeValueAsString(didDocumentRequest));

        if (!request.getBpn().equals(walletStubSettings.baseWalletBPN()) && !walletStubSettings.seedWalletsBPN().contains(request.getBpn())) {
            //post did document to portal
            ResponseEntity<Void> responseEntity = portalClient.sendDidDocument(request.getBpn(), didDocumentRequest, keycloakService.createPortalAccessToken());
            log.debug("Response of post did document status->{}", responseEntity.getStatusCode().value());
        }
    }

    /**
     * Creates a technical user with the given information.
     *
     * @param request The request object containing the information of the user to be created. It should include the external ID and the name of the user.
     * @param bpn     The business partner number associated with the user.
     */
    @SneakyThrows
    @Async
    public void createTechUser(CreateTechUserRequest request, String bpn) {
        log.debug("Request to create tech received for name -> {}, bpn ->{} waiting for 60 sec", StringEscapeUtils.escapeJava(request.getName()), StringEscapeUtils.escapeJava(bpn));

        //For this application, we do not have any external IDP(ie. keycloak)
        //BPN number will be client_id and client_secret to create OAuth token. No validation for client_secret
        //in the real world, we might create tech user in keycloak

        //create technical user details
        AuthenticationDetails authenticationDetails = AuthenticationDetails.builder()
                .authenticationServiceUrl(walletStubSettings.stubUrl() + "/oauth/token")
                .clientId(bpn)
                .clientSecret(bpn)
                .build();

        log.debug("Technical user details for bpn -> {} , user - >{}", StringEscapeUtils.escapeJava(bpn), objectMapper.writeValueAsString(authenticationDetails));

        //wait for configured time
        Thread.sleep(portalSettings.portalWaitTime() * 1000);

        // post technical user details to portal
        ResponseEntity<Void> responseEntity = portalClient.sendTechnicalUserDetails(request.getExternalId(), authenticationDetails, keycloakService.createPortalAccessToken());
        log.debug("Response of post technical user details->{}", responseEntity.getStatusCode().value());
    }
}
