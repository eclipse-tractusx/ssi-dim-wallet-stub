/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
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

package org.eclipse.tractusx.wallet.stub.dcp;

import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssuerMetadataResponse;
import org.eclipse.tractusx.wallet.stub.runtime.postgresql.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.utils.test.TestUtils;
import org.junit.jupiter.api.Assertions;
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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = { WalletStubApplication.class })
@ContextConfiguration(initializers = { TestContextInitializer.class })
public class DCPTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private WalletStubSettings walletStubSettings;

    @Autowired
    private DidDocumentService didDocumentService;


    @Test
    void testIssuerMetadata() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<IssuerMetadataResponse> response = restTemplate.exchange("/api/v1.0.0/dcp/"+baseWalletBPN+"/metadata", HttpMethod.GET, new HttpEntity<>(headers), IssuerMetadataResponse.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        IssuerMetadataResponse issuerMetadataResponse = response.getBody();
        Assertions.assertNotNull(issuerMetadataResponse);
        DidDocument didDocument = didDocumentService.getOrCreateDidDocument(baseWalletBPN);

        //validate issuer metadata
        TestUtils.validateIssuerMetadataResponse(issuerMetadataResponse, didDocument, walletStubSettings);

    }
}
