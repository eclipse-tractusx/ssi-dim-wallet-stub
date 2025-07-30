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
import lombok.extern.slf4j.Slf4j;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;
import org.eclipse.edc.security.token.jwt.CryptoConverter;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URL;
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

    private final TokenService tokenService;

    @Override
    public DidDocument getOrCreateDidDocument(String bpn) {
        try {
            Optional<DidDocument> optionalDidDocument = storage.getDidDocument(bpn);
            if (optionalDidDocument.isPresent()) {
                return optionalDidDocument.get();
            }

            return createDidDocument(bpn);
        } catch (InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private DidDocument createDidDocument(String bpn) {
        String did = CommonUtils.getDidWeb(walletStubSettings.didHost(), bpn);

        String keyId = CommonUtils.getUuid(bpn, walletStubSettings.env());
        KeyPair keyPair = keyService.getKeyPair(bpn);

        Map<String, Object> jsonObject = CryptoConverter.createJwk(keyPair).toJSONObject();
        jsonObject.put(Constants.ID, keyId);

        JWK jwk = CryptoConverter.create(jsonObject);

        //create verification method and assertion method
        VerificationMethod verificationMethod = VerificationMethod.Builder.newInstance()
                .id(URI.create(did + Constants.HASH_SEPARATOR + keyId).toString())
                .controller(did)
                .type(Constants.JSON_WEB_KEY_2020)
                .publicKeyJwk(jwk.toPublicJWK().toJSONObject())
                .build();

        //create services
        org.eclipse.edc.iam.did.spi.document.Service issuerService = new org.eclipse.edc.iam.did.spi.document.Service(did + "#"+Constants.ISSUER_SERVICE,
                Constants.ISSUER_SERVICE, CommonUtils.getIssuerServiceUrl(walletStubSettings.stubUrl(), bpn));

        org.eclipse.edc.iam.did.spi.document.Service credentialService = new org.eclipse.edc.iam.did.spi.document.Service(did + "#"+Constants.CREDENTIAL_SERVICE,
                Constants.CREDENTIAL_SERVICE, CommonUtils.getCredentialServiceUrl(walletStubSettings.stubUrl()));

        //create a did document
        DidDocument didDocument = DidDocument.Builder.newInstance()
                .id(did)
                .service(List.of(credentialService, issuerService))
                //We need to change once we have separate keys for authentication and assertion
                .authentication(List.of(verificationMethod.getId()))
                .assertionMethod(List.of(verificationMethod.getId()))
                .verificationMethod(List.of(verificationMethod))
                .context(walletStubSettings.didDocumentContextUrls().stream().map(URL::toString).toList())
                .build();
        storage.saveDidDocument(bpn, didDocument);
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

    @Override
    public DidDocument updateDidDocumentService(org.eclipse.edc.iam.did.spi.document.Service service, String token) {

        // Validate the token and extract BPN
        String bpn = tokenService.getBpnFromToken(token).orElseThrow(() -> new SecurityException("Invalid token: BPN not found"));

        DidDocument didDocument = getOrCreateDidDocument(bpn);
        List<org.eclipse.edc.iam.did.spi.document.Service> existingServices = didDocument.getService();

        // Check if the service already exists in the DID document, remove it if it does, and then add the new or updated service
        boolean serviceExists = existingServices.removeIf(s -> s.getType().equals(service.getType()));
        if (serviceExists) {
            log.debug("Updated existing service in DID document for bpn: {}, Service type: {}", bpn, service.getType());
        } else {
            log.debug("Added new service to DID document for bpn: {}, Service type: {}", bpn, service.getType());
        }
        existingServices.add(service);
        storage.saveDidDocument(bpn, didDocument);
        return didDocument;
    }
}
