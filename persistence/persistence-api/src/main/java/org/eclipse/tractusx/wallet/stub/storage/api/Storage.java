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

package org.eclipse.tractusx.wallet.stub.storage.api;

import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;

import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface Storage {

    /**
     * Retrieves a map of all DID Documents stored in the storage.
     *
     * @return A Map containing the DIDs as keys and their corresponding DID Documents as values.
     * If no DID Documents are found, returns an empty Map.
     */
    Map<String, DidDocument> getAllDidDocumentMap();

    /**
     * Saves the provided JWT credential as a Verifiable Credential (vcId) in the store.
     *
     * @param vcId      The Verifiable Credential ID associated with the JWT credential.
     * @param jwt       The JWT credential to be saved.
     * @param holderDid The DID of the holder.
     * @param type      The type of the credential.
     */
    void saveCredentialAsJwt(String vcId, String jwt, String holderDid, String type);

    /**
     * Retrieves the JWT credential associated with the provided Verifiable Credential ID (vcId).
     *
     * @param vcId The Verifiable Credential ID.
     * @return An Optional containing the JWT credential associated with the provided vcId if found, otherwise an empty Optional.
     */
    Optional<String> getCredentialAsJwt(String vcId);


    /**
     * Saves the provided Verifiable Credential in the store associated with the holder DID and type.
     *
     * @param vcId       Credential id.
     * @param credential The Verifiable Credential to be saved.
     * @param holderDid  The DID of the holder.
     * @param type       The type of the credential.
     */
    void saveCredentials(String vcId, CustomCredential credential, String holderDid, String type);

    /**
     * Retrieves the Verifiable Credential associated with the provided holder DID and type.
     *
     * @param holderDid The DID of the holder.
     * @param type      The type of the credential.
     * @return An Optional containing the Verifiable Credential if found, otherwise an empty Optional.
     */
    Optional<CustomCredential> getCredentialsByHolderDidAndType(String holderDid, String type);

    /**
     * Retrieves the JWT credential associated with the provided DID and type.
     *
     * @param holderDid The DID of the holder.
     * @param type      The type of the credential.
     * @return An Optional containing a Pair of the Verifiable Credential ID and the JWT credential if found, otherwise an empty Optional.
     */
    Optional<Pair<String, String>> getCredentialsAsJwtByHolderDidAndType(String holderDid, String type);


    /**
     * Retrieves the Verifiable Credential associated with the provided Verifiable Credential ID (vcId).
     *
     * @param vcId The Verifiable Credential ID.
     * @return An Optional containing the Verifiable Credential associated with the provided vcId if found, otherwise an empty Optional.
     */
    Optional<CustomCredential> getVerifiableCredentials(String vcId);


    /**
     * Saves the provided KeyPair in the storage associated with the DID.
     *
     * @param did     The DID for which the KeyPair is being saved.
     * @param bpn     The Business Partner Number (may be null).
     * @param keyPair The KeyPair to be saved.
     */
    void saveKeyPair(String did, String bpn, KeyPair keyPair);


    /**
     * Saves the provided DID Document in the storage associated with the DID.
     *
     * @param did         The Decentralized Identifier for which the DID Document is saved.
     * @param didDocument The DID Document to be saved.
     */
    void saveDidDocument(String did, DidDocument didDocument);


    /**
     * Retrieves a KeyPair associated with the provided DID.
     *
     * @param did the Decentralized Identifier
     * @return an Optional containing the KeyPair associated with the provided DID if found, otherwise an empty Optional
     */
    Optional<KeyPair> getKeyPair(String did);


    /**
     * Retrieves the DID Document associated with the provided DID from the storage.
     *
     * @param did The Decentralized Identifier for which to retrieve the DID Document.
     * @return An Optional containing the DID Document associated with the provided did. If no DID Document is found, return an empty Optional.
     */
    Optional<DidDocument> getDidDocument(String did);

    /**
     * Retrieves a list of Verifiable Credentials associated with the provided holder DID.
     *
     * @param holderDid The DID of the holder.
     * @return A list of CustomCredential objects for the holder.
     */
    List<CustomCredential> getVcIdAndTypesByHolderDid(String holderDid);
}
