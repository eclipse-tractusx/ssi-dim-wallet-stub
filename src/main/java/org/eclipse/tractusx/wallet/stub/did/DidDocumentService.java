/*
 *   *******************************************************************************
 *    Copyright (c) 2024 Cofinity-X
 *    Copyright (c) 2024 Contributors to the Eclipse Foundation
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

package org.eclipse.tractusx.wallet.stub.did;


import com.nimbusds.jose.jwk.JWK;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.edc.security.token.jwt.CryptoConverter;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.key.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class DidDocumentService {

    private final KeyService keyService;

    private final WalletStubSettings walletStubSettings;

    private final Storage storage;

    @SneakyThrows
    public DidDocument getDidDocument(String issuerBpn) {
        Optional<DidDocument> optionalDidDocument = storage.getDidDocument(issuerBpn);
        if (optionalDidDocument.isPresent()) {
            return optionalDidDocument.get();
        }

        String did = CommonUtils.getDidWeb(walletStubSettings.didHost(), issuerBpn);

        String keyId = CommonUtils.getUuid(issuerBpn, walletStubSettings.env());
        KeyPair keyPair = keyService.getKeyPair(issuerBpn);

        Map<String, Object> jsonObject = CryptoConverter.createJwk(keyPair).toJSONObject();
        jsonObject.put(StringPool.ID, keyId);

        JWK jwk = CryptoConverter.create(jsonObject);

        //create verification method
        VerificationMethod verificationMethod = VerificationMethod.Builder.newInstance()
                .id(URI.create(did + StringPool.HASH_SEPARATOR + keyId).toString())
                .controller(did)
                .type(StringPool.JSON_WEB_KEY_2020)
                .publicKeyJwk(jwk.toPublicJWK().toJSONObject())
                .build();


        //create service
        org.eclipse.edc.iam.did.spi.document.Service service = new org.eclipse.edc.iam.did.spi.document.Service(walletStubSettings.stubUrl() + "#credential-service",
                StringPool.CREDENTIAL_SERVICE, walletStubSettings.stubUrl() + "/api");


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
}
