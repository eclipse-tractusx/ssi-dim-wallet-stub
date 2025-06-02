/*
 *   *******************************************************************************
 *    Copyright (c) 2025 Cofinity-X
 *    Copyright (c) 2025 LKS Next
 *    Copyright (c) 2025 Contributors to the Eclipse Foundation
 *
 *    See the NOTICE file(s) distributed with this work for additional
 *    information regarding copyright ownership.
 *
 *    This program and the accompanying materials are made available under the
 *    terms of the Apache License, Version 2.0 which is available at
 *    https://www.apache.org/licenses/LICENSE-2.0.
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *   ******************************************************************************
 *
 */

package org.eclipse.tractusx.wallet.stub.did.impl;


import com.nimbusds.jose.jwk.JWK;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.edc.security.token.jwt.CryptoConverter;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.impl.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class DidDocumentServiceImpl implements DidDocumentService {

    private final KeyService keyService;

    private final WalletStubSettings walletStubSettings;

    private final Storage storage;

    @Override
    public DidDocument getOrCreateDidDocument(String issuerBpn) {
        try {
            Optional<DidDocument> optionalDidDocument = storage.getDidDocument(issuerBpn);
            if (optionalDidDocument.isPresent()) {
                return optionalDidDocument.get();
            }

            return createDidDocument(issuerBpn);
        } catch (InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private DidDocument createDidDocument(String issuerBpn) {
        String did = CommonUtils.getDidWeb(walletStubSettings.didHost(), issuerBpn);

        String keyId = CommonUtils.getUuid(issuerBpn, walletStubSettings.env());
        KeyPair keyPair = keyService.getKeyPair(issuerBpn);

        Map<String, Object> jsonObject = CryptoConverter.createJwk(keyPair).toJSONObject();
        jsonObject.put(Constants.ID, keyId);

        JWK jwk = CryptoConverter.create(jsonObject);

        //create verification method
        VerificationMethod verificationMethod = VerificationMethod.Builder.newInstance()
                .id(URI.create(did + Constants.HASH_SEPARATOR + keyId).toString())
                .controller(did)
                .type(Constants.JSON_WEB_KEY_2020)
                .publicKeyJwk(jwk.toPublicJWK().toJSONObject())
                .build();


        //create service
        org.eclipse.edc.iam.did.spi.document.Service service = new org.eclipse.edc.iam.did.spi.document.Service(walletStubSettings.stubUrl() + "#credential-service",
                Constants.CREDENTIAL_SERVICE, walletStubSettings.stubUrl() + "/api");


        //create document
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id(did)
                .service(List.of(service))
                .authentication(List.of(verificationMethod.getId()))
                .verificationMethod(List.of(verificationMethod))
                .context(List.of("https://www.w3.org/ns/did/v1"))
                .build();
        storage.saveDidDocument(issuerBpn, didDocument);
        return didDocument;
    }

    @Override
    public Optional<DidDocument> getDidDocument(String bpn) {
        try {
            log.debug("Did document requested for bpn ->{}", bpn);
            return storage.getDidDocument(bpn);
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }
}
