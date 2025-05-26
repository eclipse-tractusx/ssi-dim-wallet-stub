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

package org.eclipse.tractusx.wallet.stub.portal.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.iam.did.spi.document.Service;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.portal.api.KeycloakService;
import org.eclipse.tractusx.wallet.stub.portal.api.PortalStubService;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.AuthenticationDetails;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.CreateTechUserRequest;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.DidDocumentRequest;
import org.eclipse.tractusx.wallet.stub.portal.api.dto.SetupDimRequest;
import org.eclipse.tractusx.wallet.stub.portal.impl.PortalClient;
import org.eclipse.tractusx.wallet.stub.portal.impl.PortalSettings;
import org.eclipse.tractusx.wallet.stub.portal.impl.PortalStubServiceImpl;
import org.eclipse.tractusx.wallet.stub.utils.test.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;

import java.util.List;

class PortalUnitTest {

    @Test
    @DisplayName("Test wallet creation and verify did document should be pushed on portal API")
    void testCreateWalletAndVerifyPortalApiCall() {

        WalletStubSettings walletStubSettings = Mockito.mock(WalletStubSettings.class);
        PortalClient portalClient = Mockito.mock(PortalClient.class);
        KeycloakService keycloakService = Mockito.mock(KeycloakService.class);
        PortalSettings portalSettings = Mockito.mock(PortalSettings.class);
        DidDocumentService didDocumentService = Mockito.mock(DidDocumentService.class);

        PortalStubService portalStubService = new PortalStubServiceImpl(portalClient, new ObjectMapper(), portalSettings, walletStubSettings, didDocumentService, keycloakService);


        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("did:web:localhost:abc")
                .service(List.of(new Service()))
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        Mockito.when(walletStubSettings.didHost()).thenReturn("localhost");
        Mockito.when(walletStubSettings.seedWalletsBPN()).thenReturn(List.of());

        Mockito.when(didDocumentService.getDidDocument(Mockito.anyString())).thenReturn(didDocument);

        String bpn = TestUtils.getRandomBpmNumber();
        SetupDimRequest request = new SetupDimRequest();
        request.setBpn(bpn);
        request.setCompanyName("some wallet");
        request.setDidDocumentLocation("localhost");

        ResponseEntity responseEntity = Mockito.mock(ResponseEntity.class);
        Mockito.when(responseEntity.getStatusCode()).thenReturn(HttpStatusCode.valueOf(200));
        Mockito.when(portalClient.sendDidDocument(Mockito.anyString(), Mockito.any(DidDocumentRequest.class), Mockito.anyString())).thenReturn(responseEntity);
        Mockito.when(keycloakService.createPortalAccessToken()).thenReturn("token");
        Assertions.assertDoesNotThrow(() -> portalStubService.setupDim(request));

        Mockito.verify(portalClient, Mockito.times(1)).sendDidDocument(Mockito.anyString(), Mockito.any(DidDocumentRequest.class), Mockito.anyString());
    }

    @Test
    @DisplayName("Test tech user creation and verify tech user detail should be pushed on portal API")
    void testCreateTechUserAndVerifyPortalApiCall() {

        WalletStubSettings walletStubSettings = Mockito.mock(WalletStubSettings.class);
        PortalClient portalClient = Mockito.mock(PortalClient.class);
        KeycloakService keycloakService = Mockito.mock(KeycloakService.class);
        PortalSettings portalSettings = Mockito.mock(PortalSettings.class);
        DidDocumentService didDocumentService = Mockito.mock(DidDocumentService.class);

        PortalStubService portalStubService = new PortalStubServiceImpl(portalClient, new ObjectMapper(), portalSettings, walletStubSettings, didDocumentService, keycloakService);


        String bpn = TestUtils.getRandomBpmNumber();
        CreateTechUserRequest request = new CreateTechUserRequest();
        request.setExternalId(bpn);
        request.setName(bpn);

        ResponseEntity responseEntity = Mockito.mock(ResponseEntity.class);
        Mockito.when(responseEntity.getStatusCode()).thenReturn(HttpStatusCode.valueOf(200));
        Mockito.when(portalClient.sendTechnicalUserDetails(Mockito.anyString(), Mockito.any(AuthenticationDetails.class), Mockito.anyString())).thenReturn(responseEntity);
        Mockito.when(keycloakService.createPortalAccessToken()).thenReturn("token");
        Assertions.assertDoesNotThrow(() -> portalStubService.createTechUser(request, bpn));

        Mockito.verify(portalClient, Mockito.times(1)).sendTechnicalUserDetails(Mockito.anyString(), Mockito.any(AuthenticationDetails.class), Mockito.anyString());
    }
}
