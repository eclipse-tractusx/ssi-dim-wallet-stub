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

package org.eclipse.tractusx.wallet.stub.bdrs.test;

import com.nimbusds.jwt.JWTClaimsSet;
import org.eclipse.tractusx.wallet.stub.bdrs.impl.BDRSServiceImpl;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;

@SpringBootTest
public class BDRSServiceTest {

    @MockitoBean
    private Storage storage;

    @MockitoBean
    private DidDocumentService didDocumentService;

    @MockitoBean
    private TokenService tokenService;

    @Autowired
    private BDRSServiceImpl bdrsService;

    @Test
    public void getBpnDirectoryTest_throwIllegalArgumentException() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
           bdrsService.getBpnDirectory("","");
        });
    }

    @Test
    public void getBpnDirectoryTest_returnFilteredResponse() {
        Map<String, Object> vp = new HashMap<>();
        Map<String, Object> vc = new HashMap<>();
        Map<String, String> holder = new HashMap<>();
        holder.put(Constants.HOLDER_IDENTIFIER, "a");
        List<String> list = new ArrayList();
        list.add("a");
        vp.put(Constants.VERIFIABLE_CREDENTIAL_CAMEL_CASE, list);
        vc.put(Constants.TYPE, list);
        vc.put(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE, holder);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.VP, vp)
                .claim(Constants.VC, vc)
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);
        when(didDocumentService.getDidDocument(anyString())).thenReturn(null);

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .build();
        DidDocument didDocument2 = DidDocument.Builder.newInstance()
                .id("2")
                .build();
        Map<String, DidDocument> didDocumentMap = new HashMap<>();
        didDocumentMap.put("a", didDocument);
        didDocumentMap.put("b", didDocument);
        when(storage.getAllDidDocumentMap()).thenReturn(didDocumentMap);
        Map<String, String> response = bdrsService.getBpnDirectory("a", "a");

        Assertions.assertEquals(response.get("a"), didDocumentMap.get("a").getId());
        Assertions.assertEquals(1, response.size());
    }

    @Test
    public void getBpnDirectoryTest_returnResponse() {
        Map<String, Object> vp = new HashMap<>();
        Map<String, Object> vc = new HashMap<>();
        Map<String, String> holder = new HashMap<>();
        holder.put(Constants.HOLDER_IDENTIFIER, "a");
        List<String> list = new ArrayList();
        list.add("a");
        vp.put(Constants.VERIFIABLE_CREDENTIAL_CAMEL_CASE, list);
        vc.put(Constants.TYPE, list);
        vc.put(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE, holder);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("1")
                .issuer("")
                .expirationTime(new Date(System.currentTimeMillis() + 60))
                .claim(Constants.VP, vp)
                .claim(Constants.VC, vc)
                .build();
        when(tokenService.verifyTokenAndGetClaims(anyString())).thenReturn(jwtClaimsSet);
        when(didDocumentService.getDidDocument(anyString())).thenReturn(null);

        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id("1")
                .build();
        DidDocument didDocument2 = DidDocument.Builder.newInstance()
                .id("2")
                .build();
        Map<String, DidDocument> didDocumentMap = new HashMap<>();
        didDocumentMap.put("a", didDocument);
        didDocumentMap.put("b", didDocument);
        when(storage.getAllDidDocumentMap()).thenReturn(didDocumentMap);
        Map<String, String> response = bdrsService.getBpnDirectory("a", "");

        Assertions.assertEquals(response.get("a"), didDocumentMap.get("a").getId());
        Assertions.assertEquals(response.get("b"), didDocumentMap.get("b").getId());
        Assertions.assertEquals(2, response.size());
    }
}
