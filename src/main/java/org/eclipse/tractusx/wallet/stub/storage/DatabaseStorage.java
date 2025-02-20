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

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.dao.entity.CustomCredentialEntity;
import org.eclipse.tractusx.wallet.stub.dao.entity.DidDocumentEntity;
import org.eclipse.tractusx.wallet.stub.dao.entity.HolderCredentialAsJWTEntity;
import org.eclipse.tractusx.wallet.stub.dao.entity.HolderCredentialEntity;
import org.eclipse.tractusx.wallet.stub.dao.entity.JWTCredentialEntity;
import org.eclipse.tractusx.wallet.stub.dao.entity.KeyPairEntity;
import org.eclipse.tractusx.wallet.stub.dao.repository.*;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
@Profile("database")
public class DatabaseStorage implements Storage{

    private final KeyPairRepository keyPairRepository;

    private final DidDocumentRepository didDocumentRepository;

    private final CustomCredentialRepository customCredentialRepository;

    private final JWTCredentialRepository jwtCredentialRepository;

    private final HolderCredentialRepository holderCredentialRepository;

    private final HolderCredentialAsJWTRepository holderCredentialAsJWTRepository;


    private static String getMapKey(String holderBpn, String type) {
        return holderBpn + "###" + type;
    }

    @Override
    public Map<String, DidDocument> getAllDidDocumentMap() {
        List<DidDocumentEntity> didDocumentEntityList = didDocumentRepository.findAll();
        Map<String,DidDocument> allDidDocumentMap = new ConcurrentHashMap<>();
        for(DidDocumentEntity didDocumentEntity: didDocumentEntityList){
            DidDocument didDocument = didDocumentEntity.getDidDocument();
            allDidDocumentMap.put(didDocumentEntity.getBpn(), didDocument);
        }
        return allDidDocumentMap;
    }

    @Override
    public void saveCredentialAsJwt(String vcId, String jwt, String holderBPn, String type) {
        String key = getMapKey(holderBPn, type);
        holderCredentialAsJWTRepository.save(new HolderCredentialAsJWTEntity(key, jwt));
        if(jwtCredentialRepository.findByVcId(vcId) == null){
            jwtCredentialRepository.save(new JWTCredentialEntity(vcId, jwt));
        }
    }

    @Override
    public Optional<String> getCredentialAsJwt(String vcId) {
        JWTCredentialEntity jwtCredentialEntity = jwtCredentialRepository.findByVcId(vcId);
        if(jwtCredentialEntity == null){
            return Optional.empty();
        }
        return Optional.ofNullable(jwtCredentialEntity.getJwt());
    }

    @Override
    public void saveCredentials(String vcId, CustomCredential credential, String holderBpn, String type) {
        String key = getMapKey(holderBpn, type);
        holderCredentialRepository.save(new HolderCredentialEntity(key,credential));
        if(customCredentialRepository.findByVcId(vcId) == null){
            customCredentialRepository.save(new CustomCredentialEntity(vcId,credential));
        }
    }

    @Override
    public Optional<CustomCredential> getCredentialsByHolderBpnAndType(String holderBpn, String type) {
        HolderCredentialEntity holderCredentialEntity = holderCredentialRepository.findByKey(getMapKey(holderBpn, type));
        if(holderCredentialEntity == null){
            return Optional.empty();
        }
        return Optional.ofNullable(holderCredentialEntity.getCredential());
    }

    @Override
    public Optional<String> getCredentialsAsJwtByHolderBpnAndType(String holderBpn, String type) {
        HolderCredentialAsJWTEntity holderCredentialAsJWTEntity = holderCredentialAsJWTRepository.findByKey(getMapKey(holderBpn,type));
        if(holderCredentialAsJWTEntity == null){
            return Optional.empty();
        }
        return Optional.ofNullable(holderCredentialAsJWTEntity.getJwt());
    }

    @Override
    public Optional<CustomCredential> getVerifiableCredentials(String vcId) {
        CustomCredentialEntity customCredentialEntity = customCredentialRepository.findByVcId(vcId);
        if(customCredentialEntity == null){
            return Optional.empty();
        }
        return Optional.ofNullable(customCredentialEntity.getCredential());
    }

    @Override
    public void saveKeyPair(String bpn, KeyPair keyPair) {
        try {
            // Convert keys to Base64 strings (or byte arrays if preferred)
            String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

            KeyPairEntity keyPairEntity = new KeyPairEntity(bpn, publicKeyBase64, privateKeyBase64);
            keyPairRepository.save(keyPairEntity);
        } catch (Exception e) {
            log.debug("Error saving KeyPair: {}", e.getMessage());
        }
    }

    @Override
    public void saveDidDocument(String bpn, DidDocument didDocument) {
        didDocumentRepository.save(new DidDocumentEntity(bpn, didDocument));

    }

    @Override
    public Optional<KeyPair> getKeyPair(String bpn) {
        try {
            // Retrieve the KeyPairEntity from the database
            KeyPairEntity keyPairEntity = keyPairRepository.findByBpn(bpn);

            if (keyPairEntity != null) {
                // Decode the Base64 strings into byte arrays
                byte[] privateKeyBytes = Base64.getDecoder().decode(keyPairEntity.getPrivateKey());
                byte[] publicKeyBytes = Base64.getDecoder().decode(keyPairEntity.getPublicKey());

                // Recreate the private and public keys from the byte arrays
                PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
                PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

                return Optional.of(new KeyPair(publicKey, privateKey));
            } else {
                log.debug("KeyPair not found");
                return Optional.empty();
            }
        } catch (Exception e) {
            log.debug("Error retrieving KeyPair: {}", e.getMessage());
            return Optional.empty();
        }

    }

    @Override
    public Optional<DidDocument> getDidDocument(String bpn) {
        DidDocumentEntity didDocumentEntity = didDocumentRepository.findByBpn(bpn);
        if(didDocumentEntity == null){
            return Optional.empty();
        }
        return Optional.ofNullable(didDocumentEntity.getDidDocument());
    }

}
