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
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.test.TestUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
public class PortalUnitTest {

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private WalletStubSettings walletStubSettings;

    @MockitoBean
    private PortalClient portalClient;

    @MockitoBean
    private KeycloakService keycloakService;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private ResponseEntity responseEntity;

    @Autowired
    private PortalStubService portalStubService;

    @Test
    @DisplayName("Test wallet creation and verify did document should be pushed on portal API")
    void testCreateWalletAndVerifyPortalApiCall() {
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("did:web:localhost:abc")
                .service(List.of(new Service()))
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();

        when(walletStubSettings.didHost()).thenReturn("localhost");
        when(walletStubSettings.seedWalletsBPN()).thenReturn(List.of());

        when(didDocumentService.getDidDocument(anyString())).thenReturn(didDocument);

        String bpn = TestUtils.getRandomBpmNumber();
        SetupDimRequest request = new SetupDimRequest();
        request.setBpn(bpn);
        request.setCompanyName("some wallet");
        request.setDidDocumentLocation("localhost");

        when(responseEntity.getStatusCode()).thenReturn(HttpStatusCode.valueOf(200));
        when(portalClient.sendDidDocument(anyString(), any(DidDocumentRequest.class), anyString())).thenReturn(responseEntity);
        when(keycloakService.createPortalAccessToken()).thenReturn("token");
        assertDoesNotThrow(() -> portalStubService.setupDim(request));

        verify(portalClient, times(1)).sendDidDocument(anyString(), any(DidDocumentRequest.class), anyString());
    }

    @Test
    @DisplayName("Test tech user creation and verify tech user detail should be pushed on portal API")
    void testCreateTechUserAndVerifyPortalApiCall() {
        String bpn = TestUtils.getRandomBpmNumber();
        CreateTechUserRequest request = new CreateTechUserRequest();
        request.setExternalId(bpn);
        request.setName(bpn);

        when(responseEntity.getStatusCode()).thenReturn(HttpStatusCode.valueOf(200));
        when(portalClient.sendTechnicalUserDetails(anyString(), any(AuthenticationDetails.class), anyString())).thenReturn(responseEntity);
        when(keycloakService.createPortalAccessToken()).thenReturn("token");
        assertDoesNotThrow(() -> portalStubService.createTechUser(request, bpn));

        verify(portalClient, times(1)).sendTechnicalUserDetails(anyString(), any(AuthenticationDetails.class), anyString());
    }
}
