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

package org.eclipse.tractusx.wallet.stub.did;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.iam.did.spi.document.Service;
import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.runtime.postgresql.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
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
class DidTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private TokenSettings tokenSettings;

    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private WalletStubSettings walletStubSettings;

    @Autowired
    private Storage storage;

    @Autowired
    private DidDocumentService didDocumentService;

    @Test
    void testUpdateDidDocument() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, TestUtils.createAOauthToken(baseWalletBPN, restTemplate, tokenService, tokenSettings));

        Service service = new Service();
        service.setId("1");
        service.setServiceEndpoint("http://localhost:8080/api");
        service.setType("some-dummy-type");
        HttpEntity<Service> entity = new HttpEntity<>(service, headers);

        didDocumentService.getOrCreateDidDocument(baseWalletBPN);
        ResponseEntity<DidDocument> response = restTemplate.exchange("/api/v1.0.0/dcp/did-document/services", HttpMethod.PUT, entity, DidDocument.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        DidDocument updatedDidDocument = response.getBody();
        Assertions.assertNotNull(updatedDidDocument);

        Assertions.assertTrue(updatedDidDocument.getService().stream()
                        .anyMatch(s -> s.getId().equals(service.getId()) && s.getType().equals(service.getType())
                                && s.getServiceEndpoint().equals(service.getServiceEndpoint())),
                "Updated Did Document should contain the new service");

        //try with existing service
        Service updatedService = new Service();
        updatedService.setId("4");
        updatedService.setServiceEndpoint("http://localhost:8080/updated-api");

        //service type remains the same
        updatedService.setType("some-dummy-type");
        entity = new HttpEntity<>(updatedService, headers);

        response = restTemplate.exchange("/api/v1.0.0/dcp/did-document/services", HttpMethod.PUT, entity, DidDocument.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());

        updatedDidDocument = response.getBody();
        Assertions.assertNotNull(updatedDidDocument);

        Assertions.assertTrue(updatedDidDocument.getService().stream()
                        .anyMatch(s -> s.getId().equals(updatedService.getId()) && s.getType().equals(updatedService.getType())
                                && s.getServiceEndpoint().equals(updatedService.getServiceEndpoint())),
                "Updated Did Document should contain the new service");
    }
}
