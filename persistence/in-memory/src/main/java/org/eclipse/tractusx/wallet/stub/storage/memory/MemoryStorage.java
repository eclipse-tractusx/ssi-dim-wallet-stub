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

package org.eclipse.tractusx.wallet.stub.storage.memory;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The in-memory storage
 */
@Service
@Slf4j
public class MemoryStorage implements Storage {


    //To store KeyPair: DID as a key and keypair as value
    private static final Map<String, KeyPair> KEY_STORE = new ConcurrentHashMap<>();

    //To store DIdDocument: DID as a key and did document as a value
    private static final Map<String, DidDocument> DID_DOCUMENT_STORE = new ConcurrentHashMap<>();

    //To store VerifiableCredential: VCId as a key and VC as a value
    private static final Map<String, CustomCredential> CREDENTIAL_STORE = new ConcurrentHashMap<>();

    //To store JWT: VCId as a key and JWT as a value
    private static final Map<String, String> JWT_CREDENTIAL_STORE = new ConcurrentHashMap<>();

    //To store VC for holder, DID###type as a key and VC as value
    private static final Map<String, CustomCredential> HOLDER_CREDENTIAL_STORE = new ConcurrentHashMap<>();

    //To store VC as JWT for holder, DID###type as a key and JWT as value
    private static final Map<String, Pair<String, String>> HOLDER_CREDENTIAL_AS_JWT_STORE = new ConcurrentHashMap<>();


    private static String getMapKey(String holderBpn, String type) {
        return holderBpn + "###" + type;
    }

    @Override
    public Map<String, DidDocument> getAllDidDocumentMap() {
        return DID_DOCUMENT_STORE;
    }

    @Override
    public void saveCredentialAsJwt(String vcId, String jwt, String holderDid, String type) {
        String key = getMapKey(holderDid, type);
        HOLDER_CREDENTIAL_AS_JWT_STORE.put(key, Pair.of(vcId, jwt));
        JWT_CREDENTIAL_STORE.computeIfAbsent(vcId, k -> jwt);
    }

    @Override
    public Optional<String> getCredentialAsJwt(String vcId) {
        return Optional.ofNullable(JWT_CREDENTIAL_STORE.get(vcId));
    }

    @Override
    public void saveCredentials(String vcId, CustomCredential credential, String holderDid, String type) {
        String key = getMapKey(holderDid, type);
        HOLDER_CREDENTIAL_STORE.put(key, credential);
        CREDENTIAL_STORE.computeIfAbsent(vcId, k -> credential);
    }

    @Override
    public Optional<CustomCredential> getCredentialsByHolderDidAndType(String holderDid, String type) {
        return Optional.ofNullable(HOLDER_CREDENTIAL_STORE.get(getMapKey(holderDid, type)));
    }

    @Override
    public Optional<Pair<String, String>> getCredentialsAsJwtByHolderDidAndType(String holderDid, String type) {
        return Optional.ofNullable(HOLDER_CREDENTIAL_AS_JWT_STORE.get(getMapKey(holderDid, type)));
    }

    @Override
    public Optional<CustomCredential> getVerifiableCredentials(String vcId) {
        return Optional.ofNullable(CREDENTIAL_STORE.get(vcId));
    }

    @Override
    public void saveKeyPair(String did, String bpn, KeyPair keyPair) {
        KEY_STORE.put(did, keyPair);
    }

    @Override
    public void saveDidDocument(String did, DidDocument didDocument) {
        DID_DOCUMENT_STORE.put(did, didDocument);
    }

    @Override
    public Optional<KeyPair> getKeyPair(String did) {
        return Optional.ofNullable(KEY_STORE.get(did));
    }

    @Override
    public Optional<DidDocument> getDidDocument(String did) {
        return Optional.ofNullable(DID_DOCUMENT_STORE.get(did));
    }

    @Override
    public List<CustomCredential> getVcIdAndTypesByHolderDid(String holderDid) {
        return HOLDER_CREDENTIAL_STORE.entrySet().stream()
                .filter(e -> e.getKey().startsWith(holderDid + "###"))
                .map(Map.Entry::getValue)
                .toList();
    }
}
