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

package org.eclipse.tractusx.wallet.stub.wallet;

import org.eclipse.tractusx.wallet.stub.WalletStubApplication;
import org.eclipse.tractusx.wallet.stub.config.TestContextInitializer;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.storage.MemoryStorage;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.eclipse.tractusx.wallet.stub.utils.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ContextConfiguration;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT, classes = { WalletStubApplication.class })
@ContextConfiguration(initializers = { TestContextInitializer.class })
class WalletTest {

    @Autowired
    private WalletStubSettings walletStubSettings;

    @Autowired
    private MemoryStorage memoryStorage;

    @Autowired
    private TestRestTemplate testRestTemplate;

    @Test
    @DisplayName("Base wallet should be initialized and check did document and status list credential")
    void verifyBaseWallet() {
        String baseWalletBPN = walletStubSettings.baseWalletBPN();

        //check keypair is generated
        Assertions.assertTrue(memoryStorage.getKeyPair(baseWalletBPN).isPresent());

        //check did document is created
        Assertions.assertTrue(memoryStorage.getDidDocument(baseWalletBPN).isPresent());

        //check status list VC is created
        Assertions.assertTrue(memoryStorage.getCredentialsByHolderBpnAndType(baseWalletBPN, StringPool.STATUS_LIST_2021_CREDENTIAL).isPresent());
    }


    @Test
    @DisplayName("Wallet should be created at run time when we request for did document")
    void testWalletCreation() {
        String bpn = TestUtils.getRandomBpmNumber();
        ResponseEntity<DidDocument> responseEntity = testRestTemplate.getForEntity("/" + bpn + "/did.json", DidDocument.class);

        Assertions.assertEquals(responseEntity.getStatusCode().value(), HttpStatus.OK.value());

        Assertions.assertNotNull(responseEntity.getBody());

        //check keypair is generated
        Assertions.assertTrue(memoryStorage.getKeyPair(bpn).isPresent());

        //check did document is created
        Assertions.assertTrue(memoryStorage.getDidDocument(bpn).isPresent());
    }

    @Test
    @DisplayName("Seeded wallets should be created for the specified BPNs in the configuration")
    void verifySeedWallet(){

        for (String bpn: walletStubSettings.seedWalletsBPN()){
            //check keypair is generated
            Assertions.assertTrue(memoryStorage.getKeyPair(bpn).isPresent());

            //check did document is created
            Assertions.assertTrue(memoryStorage.getDidDocument(bpn).isPresent());

            //check status list VC is created
            Assertions.assertTrue(memoryStorage.getCredentialsByHolderBpnAndType(bpn, StringPool.STATUS_LIST_2021_CREDENTIAL).isPresent());
        }
    }

    @Test
    @DisplayName("Wallets should not be created for BPNs not included in BaseWallets or SeedWallets")
    void verifyNoSeedWallet(){

        // Generate a random BPN not included in BaseWallets or SeedWallets
        String bpnRand = TestUtils.getRandomBpmNumber();
        while (bpnRand.equals(walletStubSettings.baseWalletBPN()) && walletStubSettings.seedWalletsBPN().contains(bpnRand)){
            bpnRand = TestUtils.getRandomBpmNumber();
        }

        //check keypair is not generated
        Assertions.assertFalse(memoryStorage.getKeyPair(bpnRand).isPresent());

        //check did document is not created
        Assertions.assertFalse(memoryStorage.getDidDocument(bpnRand).isPresent());

        //check status list VC is not created
        Assertions.assertFalse(memoryStorage.getCredentialsByHolderBpnAndType(bpnRand, StringPool.STATUS_LIST_2021_CREDENTIAL).isPresent());
    }
}
