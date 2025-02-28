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

package org.eclipse.tractusx.wallet.stub.key;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.eclipse.tractusx.wallet.stub.utils.DeterministicECKeyPairGenerator;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Optional;

/**
 * This class provides methods to generate key pairs
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class KeyService {

    private final Storage storage;

    private final WalletStubSettings walletStubSettings;

    /**
     * Retrieves a KeyPair associated with the provided business partner number (bpn).
     *
     * @param bpn the business partner number
     * @return the KeyPair associated with the provided bpn, or generates a new KeyPair and saves it if no KeyPair is found
     */
    public KeyPair getKeyPair(String bpn) {
        Optional<KeyPair> optionalKeyPair = storage.getKeyPair(bpn);
        return optionalKeyPair.orElseGet(() -> {
            KeyPair keyPair = DeterministicECKeyPairGenerator.createKeyPair(bpn, walletStubSettings.env());
            storage.saveKeyPair(bpn, keyPair);
            return keyPair;
        });
    }
}
