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

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The in-memory storage
 */
@Service
public class MemoryStorage implements Storage {


    private static final ObjectMapper objectMapper = new ObjectMapper();

    //To store KeyPair: BPN as a key and keypair as value
    private static final Map<String, KeyPair> KEY_STORE = new ConcurrentHashMap<>();

    //To store DIdDocument: BPN as a key and did document as a value
    private static final Map<String, DidDocument> DID_DOCUMENT_STORE = new ConcurrentHashMap<>();

    //To store VerifiableCredential: VCId as a key and VC as a value
    private static final Map<String, CustomCredential> CREDENTIAL_STORE = new ConcurrentHashMap<>();

    //To store JWT: VCId as a key and JWT as a value
    private static final Map<String, String> JWT_CREDENTIAL_STORE = new ConcurrentHashMap<>();

    //To store VC for holder, BPN#type as a key and VC as value
    private static final Map<String, CustomCredential> HOLDER_CREDENTIAL_STORE = new ConcurrentHashMap<>();

    //To store VC as JWT for holder, BPN###type as a key and JWT as value
    private static final Map<String, String> HOLDER_CREDENTIAL_AS_JWT_STORE = new ConcurrentHashMap<>();


    private static String getMapKey(String holderBpn, String type) {
        return holderBpn + "###" + type;
    }

    @Override
    public Map<String, DidDocument> getAllDidDocumentMap() {
        return DID_DOCUMENT_STORE;
    }

    @Override
    public void saveCredentialAsJwt(String vcId, String jwt, String holderBPn, String type) {
        String key = getMapKey(holderBPn, type);
        HOLDER_CREDENTIAL_AS_JWT_STORE.put(key, jwt);
        JWT_CREDENTIAL_STORE.computeIfAbsent(vcId, k -> jwt);
    }

    @Override
    public Optional<String> getCredentialAsJwt(String vcId) {
        return Optional.ofNullable(JWT_CREDENTIAL_STORE.get(vcId));
    }

    @Override
    public void saveCredentials(String vcId, CustomCredential credential, String holderBpn, String type) {
        String key = getMapKey(holderBpn, type);
        HOLDER_CREDENTIAL_STORE.put(key, credential);
        CREDENTIAL_STORE.computeIfAbsent(vcId, k -> credential);
    }

    @Override
    public Optional<CustomCredential> getCredentialsByHolderBpnAndType(String holderBpn, String type) {
        return Optional.ofNullable(HOLDER_CREDENTIAL_STORE.get(getMapKey(holderBpn, type)));
    }

    @SneakyThrows
    @Override
    public Optional<Pair<String, String>> getCredentialsAsJwtByHolderBpnAndType(String holderBpn, String type) {
        String jwtString = HOLDER_CREDENTIAL_AS_JWT_STORE.get(getMapKey(holderBpn, type));
        if(jwtString == null) {
            return Optional.empty();
        }else {
            String payload = jwtString.split("\\.")[1];
            Map<String, Object> map = (Map<String, Object>) objectMapper.readValue(new String(Base64.getDecoder().decode(payload)), Map.class).get(Constants.VC);
            String vcId = map.get(Constants.ID).toString().split("#")[1];
            return Optional.ofNullable(Pair.of(vcId,jwtString));
        }
    }

    @Override
    public Optional<CustomCredential> getVerifiableCredentials(String vcId) {
        return Optional.ofNullable(CREDENTIAL_STORE.get(vcId));
    }

    @Override
    public void saveKeyPair(String bpn, KeyPair keyPair) {
        KEY_STORE.put(bpn, keyPair);
    }

    @Override
    public void saveDidDocument(String bpn, DidDocument didDocument) {
        DID_DOCUMENT_STORE.put(bpn, didDocument);
    }

    @Override
    public Optional<KeyPair> getKeyPair(String bpn) {
        return Optional.ofNullable(KEY_STORE.get(bpn));
    }

    @Override
    public Optional<DidDocument> getDidDocument(String bpn) {
        return Optional.ofNullable(DID_DOCUMENT_STORE.get(bpn));
    }

    @Override
    public List<CustomCredential> getVcIdAndTypesByHolderBpn(String holderBpn) {
        return HOLDER_CREDENTIAL_STORE.values().stream().filter(credential -> {
            Map<String, String> credentialSubject = (Map<String, String>) credential.get(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE);
            if (!credentialSubject.containsKey(Constants.ID)) {
                return false;
            } else {
                return credentialSubject.get(Constants.ID).toString().contains(holderBpn);
            }
        }).toList();
    }
}
