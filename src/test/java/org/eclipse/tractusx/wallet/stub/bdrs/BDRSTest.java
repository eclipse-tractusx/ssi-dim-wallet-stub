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

package org.eclipse.tractusx.wallet.stub.bdrs;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.tractusx.wallet.stub.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.edc.dto.QueryPresentationRequest;
import org.eclipse.tractusx.wallet.stub.key.KeyService;
import org.eclipse.tractusx.wallet.stub.token.TokenService;
import org.eclipse.tractusx.wallet.stub.token.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.eclipse.tractusx.wallet.stub.utils.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;
import org.springframework.test.context.ContextConfiguration;

import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;


@SuppressWarnings("rawtypes")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = {WalletStubApplication.class})
@ContextConfiguration(initializers = {TestContextInitializer.class})
class BDRSTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private TokenSettings tokenSettings;

    @Autowired
    private KeyService keyService;

    @Autowired
    private DidDocumentService didDocumentService;

    @Autowired
    private WalletStubSettings walletStubSettings;


    @Test
    @DisplayName("Test BDRS Directory API with invalid Token")
    void testDirectoryApiWithToken() {
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<QueryPresentationRequest> entity = new HttpEntity<>(headers);

        //do not pass Authorization header
        ResponseEntity<Map> response = restTemplate.exchange("/api/v1/directory/bpn-directory", HttpMethod.GET, entity, Map.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.UNAUTHORIZED.value());

        //pass invalid token
        headers.add(HttpHeaders.AUTHORIZATION, StringPool.BEARER + "Some dummy token");
        entity = new HttpEntity<>(headers);
        response = restTemplate.exchange("/api/v1/directory/bpn-directory", HttpMethod.GET, entity, Map.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.UNAUTHORIZED.value());

    }

    @Test
    @DisplayName("Test BDRS Directory API")
    void testDirectoryApi() throws URISyntaxException {
        String readScope = "read";
        String consumerBpn = TestUtils.getRandomBpmNumber();
        String providerBpn = TestUtils.getRandomBpmNumber();
        String consumerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), consumerBpn);
        String providerDid = CommonUtils.getDidWeb(walletStubSettings.didHost(), providerBpn);

        String vpToken = TestUtils.getVPToken(restTemplate, keyService, didDocumentService, tokenService, tokenSettings, consumerDid, providerDid, consumerBpn, readScope, List.of(StringPool.BPN_CREDENTIAL));
        Assertions.assertNotNull(vpToken);

        //make directory API call
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, StringPool.BEARER + vpToken);
        HttpEntity<QueryPresentationRequest> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange("/api/v1/directory/bpn-directory?bpn=" + StringUtils.join(List.of(consumerBpn, providerBpn), ", "), HttpMethod.GET, entity, Map.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        Map body = response.getBody();
        Assertions.assertNotNull(body);
        Assertions.assertEquals(2, body.size()); //we requested  bpns only, so it should return only 2
        Assertions.assertTrue(body.containsKey(consumerBpn));
        Assertions.assertTrue(body.containsKey(providerBpn));
        Assertions.assertEquals(body.get(consumerBpn).toString(), consumerDid);

        //request without request param
        response = restTemplate.exchange("/api/v1/directory/bpn-directory", HttpMethod.GET, entity, Map.class);
        Assertions.assertEquals(response.getStatusCode().value(), HttpStatus.OK.value());
        body = response.getBody();
        Assertions.assertNotNull(body);
        Assertions.assertEquals(3, body.size());
        Assertions.assertTrue(body.containsKey(walletStubSettings.baseWalletBPN())); //it should contain base wallet BPN as well
    }
}
