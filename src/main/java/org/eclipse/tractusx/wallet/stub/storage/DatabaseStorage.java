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

package org.eclipse.tractusx.wallet.stub.storage;

import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Map;
import java.util.Optional;

@Service
@Profile("database")
public class DatabaseStorage implements Storage{
    @Override
    public Map<String, DidDocument> getAllDidDocumentMap() {
        return Map.of();
    }

    @Override
    public void saveCredentialAsJwt(String vcId, String jwt, String holderBPn, String type) {

    }

    @Override
    public Optional<String> getCredentialAsJwt(String vcId) {
        return Optional.empty();
    }

    @Override
    public void saveCredentials(String vcId, CustomCredential credential, String holderBpn, String type) {

    }

    @Override
    public Optional<CustomCredential> getCredentialsByHolderBpnAndType(String holderBpn, String type) {
        return Optional.empty();
    }

    @Override
    public Optional<String> getCredentialsAsJwtByHolderBpnAndType(String holderBpn, String type) {
        return Optional.empty();
    }

    @Override
    public Optional<CustomCredential> getVerifiableCredentials(String vcId) {
        return Optional.empty();
    }

    @Override
    public void saveKeyPair(String bpn, KeyPair keyPair) {

    }

    @Override
    public void saveDidDocument(String bpn, DidDocument didDocument) {

    }

    @Override
    public Optional<KeyPair> getKeyPair(String bpn) {
        return Optional.empty();
    }

    @Override
    public Optional<DidDocument> getDidDocument(String bpn) {
        return Optional.empty();
    }
}
