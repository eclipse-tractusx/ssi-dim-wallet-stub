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

package org.eclipse.tractusx.wallet.stub.storage.postgresql;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.entity.CustomCredentialEntity;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.entity.DidDocumentEntity;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.entity.HolderCredentialAsJWTEntity;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.entity.HolderCredentialEntity;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.entity.JWTCredentialEntity;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.entity.KeyPairEntity;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.repository.CustomCredentialRepository;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.repository.DidDocumentRepository;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.repository.HolderCredentialAsJWTRepository;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.repository.HolderCredentialRepository;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.repository.JWTCredentialRepository;
import org.eclipse.tractusx.wallet.stub.dao.postgresql.repository.KeyPairRepository;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
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
public class DatabaseStorage implements Storage {

    private final KeyPairRepository keyPairRepository;

    private final DidDocumentRepository didDocumentRepository;

    private final CustomCredentialRepository customCredentialRepository;

    private final JWTCredentialRepository jwtCredentialRepository;

    private final HolderCredentialRepository holderCredentialRepository;

    private final HolderCredentialAsJWTRepository holderCredentialAsJWTRepository;


    private static String getMapKey(String holderDid, String type) {
        return holderDid + "###" + type;
    }

    @Override
    public Map<String, DidDocument> getAllDidDocumentMap() {
        List<DidDocumentEntity> didDocumentEntityList = didDocumentRepository.findAll();
        Map<String, DidDocument> allDidDocumentMap = new ConcurrentHashMap<>();
        for (DidDocumentEntity didDocumentEntity : didDocumentEntityList) {
            DidDocument didDocument = didDocumentEntity.getDidDocument();
            allDidDocumentMap.put(didDocumentEntity.getDid(), didDocument);
        }
        return allDidDocumentMap;
    }

    @Override
    public void saveCredentialAsJwt(String vcId, String jwt, String holderDid, String type) {
        String key = getMapKey(holderDid, type);
        holderCredentialAsJWTRepository.save(new HolderCredentialAsJWTEntity(key, vcId, holderDid, jwt));
        if (jwtCredentialRepository.findByVcId(vcId) == null) {
            jwtCredentialRepository.save(new JWTCredentialEntity(vcId, jwt));
        }
    }

    @Override
    public Optional<String> getCredentialAsJwt(String vcId) {
        JWTCredentialEntity jwtCredentialEntity = jwtCredentialRepository.findByVcId(vcId);
        if (jwtCredentialEntity == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(jwtCredentialEntity.getJwt());
    }

    @Override
    public void saveCredentials(String vcId, CustomCredential credential, String holderDid, String type) {
        String key = getMapKey(holderDid, type);
        holderCredentialRepository.save(new HolderCredentialEntity(key, holderDid, credential));
        if (customCredentialRepository.findByVcId(vcId) == null) {
            customCredentialRepository.save(new CustomCredentialEntity(vcId, credential));
        }
    }

    @Override
    public Optional<CustomCredential> getCredentialsByHolderDidAndType(String holderDid, String type) {
        HolderCredentialEntity holderCredentialEntity = holderCredentialRepository.findByKey(getMapKey(holderDid, type));
        if (holderCredentialEntity == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(holderCredentialEntity.getCredential());
    }

    @Override
    public Optional<Pair<String, String>> getCredentialsAsJwtByHolderDidAndType(String holderDid, String type) {
        HolderCredentialAsJWTEntity holderCredentialAsJWTEntity = holderCredentialAsJWTRepository.findByKey(getMapKey(holderDid, type));
        if (holderCredentialAsJWTEntity == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(Pair.of(holderCredentialAsJWTEntity.getVcId(), holderCredentialAsJWTEntity.getJwt()));
    }

    @Override
    public Optional<CustomCredential> getVerifiableCredentials(String vcId) {
        CustomCredentialEntity customCredentialEntity = customCredentialRepository.findByVcId(vcId);
        if (customCredentialEntity == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(customCredentialEntity.getCredential());
    }

    public void saveKeyPair(String did, String bpn, KeyPair keyPair) {
        try {
            String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            KeyPairEntity keyPairEntity = new KeyPairEntity(did, bpn, publicKeyBase64, privateKeyBase64);
            keyPairRepository.save(keyPairEntity);
        } catch (Exception e) {
            log.debug("Error saving KeyPair by did: {}", e.getMessage());
        }
    }

    @Override
    public void saveDidDocument(String did, DidDocument didDocument) {
        try {
            didDocumentRepository.save(new DidDocumentEntity(did, didDocument));
        } catch (Exception e) {
            // Ignore duplicate key violations — another thread already saved the document
            log.debug("DID document for did {} already exists, skipping save: {}", did, e.getMessage());
        }
    }

    @Override
    public Optional<KeyPair> getKeyPair(String did) {
        try {
            KeyPairEntity keyPairEntity = keyPairRepository.findByDid(did);
            if (keyPairEntity != null) {
                byte[] privateKeyBytes = Base64.getDecoder().decode(keyPairEntity.getPrivateKey());
                byte[] publicKeyBytes = Base64.getDecoder().decode(keyPairEntity.getPublicKey());
                PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
                PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                return Optional.of(new KeyPair(publicKey, privateKey));
            } else {
                log.debug("KeyPair not found for did: {}", did);
                return Optional.empty();
            }
        } catch (Exception e) {
            log.debug("Error retrieving KeyPair by did: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<DidDocument> getDidDocument(String did) {
        DidDocumentEntity didDocumentEntity = didDocumentRepository.findByDid(did);
        if (didDocumentEntity == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(didDocumentEntity.getDidDocument());
    }

    @Override
    public List<CustomCredential> getVcIdAndTypesByHolderDid(String holderDid) {
        return holderCredentialRepository.getCredentialByHolderDid(holderDid).stream().map(HolderCredentialEntity::getCredential).toList();
    }
}
