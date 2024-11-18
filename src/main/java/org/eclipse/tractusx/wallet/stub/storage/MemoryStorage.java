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

package org.eclipse.tractusx.wallet.stub.storage;

import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The in-memory storage
 */
@Service
public class MemoryStorage {


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


    /**
     * Retrieves a map of all DID Documents stored in the memory storage.
     *
     * @return A Map containing the Business Partner Numbers (bpn) as keys and their corresponding DID Documents as values.
     * If no DID Documents are found, returns an empty Map.
     */
    public Map<String, DidDocument> getAllDidDocumentMap() {
        return DID_DOCUMENT_STORE;
    }

    /**
     * Saves the provided JWT credential as a Verifiable Credential (vcId) in the memory store.
     *
     * @param vcId The Verifiable Credential ID associated with the JWT credential.
     * @param jwt  The JWT credential to be saved.
     */
    public void saveCredentialAsJwt(String vcId, String jwt, String holderBPn, String type) {
        String key = getMapKey(holderBPn, type);
        HOLDER_CREDENTIAL_AS_JWT_STORE.put(key, jwt);
        JWT_CREDENTIAL_STORE.computeIfAbsent(vcId, k -> jwt);
    }

    /**
     * Retrieves the JWT credential associated with the provided Verifiable Credential ID (vcId).
     *
     * @param vcId The Verifiable Credential ID.
     * @return An Optional containing the JWT credential associated with the provided vcId if found, otherwise an empty Optional.
     */
    public Optional<String> getCredentialAsJwt(String vcId) {
        return Optional.ofNullable(JWT_CREDENTIAL_STORE.get(vcId));
    }


    /**
     * Saves the provided Verifiable Credential in the memory store associated with the Business Partner Number (bpn).
     *
     * @param vcId       Credential id.
     * @param credential The Verifiable Credential to be saved.
     */
    public void saveCredentials(String vcId, CustomCredential credential, String holderBpn, String type) {
        String key = getMapKey(holderBpn, type);
        HOLDER_CREDENTIAL_STORE.put(key, credential);
        CREDENTIAL_STORE.computeIfAbsent(vcId, k -> credential);
    }

    public Optional<CustomCredential> getCredentialsByHolderBpnAndType(String holderBpn, String type) {
        return Optional.ofNullable(HOLDER_CREDENTIAL_STORE.get(getMapKey(holderBpn, type)));
    }

    public Optional<String> getCredentialsAsJwtByHolderBpnAndType(String holderBpn, String type) {
        return Optional.ofNullable(HOLDER_CREDENTIAL_AS_JWT_STORE.get(getMapKey(holderBpn, type)));
    }


    /**
     * Retrieves the Verifiable Credential associated with the provided Verifiable Credential ID (vcId).
     *
     * @param vcId The Verifiable Credential ID.
     * @return An Optional containing the Verifiable Credential associated with the provided vcId if found, otherwise an empty Optional.
     */
    public Optional<CustomCredential> getVerifiableCredentials(String vcId) {
        return Optional.ofNullable(CREDENTIAL_STORE.get(vcId));
    }


    /**
     * Saves the provided KeyPair in the memory storage associated with the Business Partner Number (bpn).
     *
     * @param bpn     The Business Partner Number for which the KeyPair is being saved.
     * @param keyPair The KeyPair to be saved.
     */
    public void saveKeyPair(String bpn, KeyPair keyPair) {
        KEY_STORE.put(bpn, keyPair);
    }


    /**
     * Saves the provided DID Document in the memory storage associated with the Business Partner Number (bpn).
     *
     * @param bpn         The Business Partner Number (bpn) for which the DID Document is saved.
     * @param didDocument The DID Document to be saved.
     */
    public void saveDidDocument(String bpn, DidDocument didDocument) {
        DID_DOCUMENT_STORE.put(bpn, didDocument);
    }


    /**
     * Retrieves a KeyPair associated with the provided Business Partner Number (bpn).
     *
     * @param bpn the Business Partner Number
     * @return an Optional containing the KeyPair associated with the provided bpn if found, otherwise an empty Optional
     */
    public Optional<KeyPair> getKeyPair(String bpn) {
        return Optional.ofNullable(KEY_STORE.get(bpn));
    }


    /**
     * Retrieves the DID Document associated with the provided Business Partner Number (bpn) from the memory store.
     *
     * @param bpn The business partner number (bpn) for which to retrieve the DID Document.
     * @return An Optional containing the DID Document associated with the provided bpn. If no DID Document is found, return an empty Optional.
     */
    public Optional<DidDocument> getDidDocument(String bpn) {
        return Optional.ofNullable(DID_DOCUMENT_STORE.get(bpn));
    }
}


