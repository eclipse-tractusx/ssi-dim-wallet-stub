/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
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

package org.eclipse.tractusx.wallet.stub.issuer;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.issuer.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.key.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.eclipse.tractusx.wallet.stub.token.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class IssuerCredentialService {

    private final WalletStubSettings walletStubSettings;

    private final KeyService keyService;
    private final DidDocumentService didDocumentService;
    private final Storage storage;
    private final TokenSettings tokenSettings;

    @SuppressWarnings("unchecked")
    private static String getHolderBpn(CustomCredential verifiableCredential) {
        //get Holder BPN
        Map<String, Object> subject = (Map<String, Object>) verifiableCredential.get("credentialSubject");
        if (subject.containsKey(StringPool.BPN)) {
            return subject.get(StringPool.BPN).toString();
        } else if (subject.containsKey(StringPool.HOLDER_IDENTIFIER)) {
            return subject.get(StringPool.HOLDER_IDENTIFIER).toString();
        } else {
            throw new IllegalArgumentException("Can not identify holder BPN from VC");
        }
    }

    /**
     * Issues a verifiable credential based on the provided request and issuer BPN.
     * This method creates, signs, and stores a verifiable credential as both JWT and JSON-LD formats.
     *
     * @param request   The IssueCredentialRequest containing the credential payload and other necessary information.
     * @param issuerBPN The Business Partner Number (BPN) of the issuer.
     * @return A Map containing the credential ID ("vcId") and optionally the JWT representation of the credential ("jwt").
     * If the request includes "issue", only the "vcId" is returned.
     */
    @SuppressWarnings("unchecked")
    @SneakyThrows
    public Map<String, String> issueCredential(IssueCredentialRequest request, String issuerBPN) {

        KeyPair issuerKeypair = keyService.getKeyPair(walletStubSettings.baseWalletBPN());

        DidDocument issuerDidDocument = didDocumentService.getDidDocument(issuerBPN);

        CustomCredential verifiableCredential = new CustomCredential();

        //we have two options here, user can ask only to provide VC ID or JWT and VC ID
        if (!CollectionUtils.isEmpty(request.getCredentialPayload().getIssue())) {
            verifiableCredential.putAll(request.getCredentialPayload().getIssue());
        } else {
            verifiableCredential.putAll((Map<String, Object>) request.getCredentialPayload().getIssueWithSignature().get(StringPool.CONTENT));
        }
        String holderBpn = getHolderBpn(verifiableCredential);

        DidDocument holderDidDocument = didDocumentService.getDidDocument(holderBpn);

        String type;
        List<String> types = (List<String>) verifiableCredential.get(StringPool.TYPE);
        //https://www.w3.org/TR/vc-data-model/#types As per the VC schema, types can be multiple, but index 1 should have the correct type.
        if (types.size() == 2) {
            type = types.get(1);
        } else if (types.size() == 1) {
            type = types.getFirst();
        } else {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "No type found in VC");
        }

        //sign
        String vcId = CommonUtils.getUuid(holderBpn, type);
        URI vcIdUri = URI.create(issuerDidDocument.getId() + StringPool.HASH_SEPARATOR + vcId);
        URI issuer = new URI("did:web:" + walletStubSettings.didHost() + ":" + walletStubSettings.baseWalletBPN());

        verifiableCredential.put(StringPool.ID, vcIdUri.toString());
        verifiableCredential.put("issuer", issuer.toString());

        //sign JWT
        JWSHeader membershipTokenHeader = new JWSHeader.Builder(JWSAlgorithm.ES256K)
                .type(JOSEObjectType.JWT)
                .keyID(issuerDidDocument.getVerificationMethod().getFirst().getId())
                .build();

        //time config
        Date time = new Date();
        Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

        //claims
        JWTClaimsSet membershipTokenBody = new JWTClaimsSet.Builder()
                .issueTime(time)
                .jwtID(UUID.randomUUID().toString())
                .audience(List.of(issuerDidDocument.getId(), holderDidDocument.getId()))
                .expirationTime(expiryTime)
                .claim(StringPool.BPN, holderBpn)
                .claim(StringPool.VC, verifiableCredential)
                .issuer(issuerDidDocument.getId())
                .subject(issuerDidDocument.getId())
                .build();

        SignedJWT vcJWT = new SignedJWT(membershipTokenHeader, membershipTokenBody);
        JWSSigner signer = new ECDSASigner((ECPrivateKey) issuerKeypair.getPrivate());
        signer.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
        vcJWT.sign(signer);
        String vcAsJwt = vcJWT.serialize();

        //save JWT
        storage.saveCredentialAsJwt(vcIdUri.toString(), vcAsJwt, holderBpn, type);

        //save JSON-LD
        storage.saveCredentials(vcIdUri.toString(), verifiableCredential, holderBpn, type);

        if (!CollectionUtils.isEmpty(request.getCredentialPayload().getIssueWithSignature())) {
            return Map.of(StringPool.ID, vcId, StringPool.JWT, vcAsJwt);
        } else {
            return Map.of(StringPool.ID, vcId);
        }
    }

    @SneakyThrows
    public Optional<String> signCredential(String credentialId) {
        DidDocument issuerDidDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());
        URI vcIdUri = URI.create(issuerDidDocument.getId() + StringPool.HASH_SEPARATOR + credentialId);
        return storage.getCredentialAsJwt(vcIdUri.toString());
    }

    @SneakyThrows
    public GetCredentialsResponse getCredential(String externalCredentialId) {
        DidDocument issuerDidDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());
        URI vcIdUri = URI.create(issuerDidDocument.getId() + StringPool.HASH_SEPARATOR + externalCredentialId);
        Optional<String> jwtVc = storage.getCredentialAsJwt(vcIdUri.toString());
        if (jwtVc.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No credential found for credentialId -> " + externalCredentialId);
        }
        Optional<CustomCredential> optionalCustomVerifiableCredential = storage.getVerifiableCredentials(vcIdUri.toString());

        if (optionalCustomVerifiableCredential.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No credential found for credentialId -> " + externalCredentialId);
        }
        return GetCredentialsResponse.builder()
                .signingKeyId(issuerDidDocument.getVerificationMethod().getFirst().getId())
                .revocationStatus("false")
                .verifiableCredential(jwtVc.get())
                .credential(optionalCustomVerifiableCredential.get())
                .build();
    }

    public String storeCredential(IssueCredentialRequest request, String holderBpn) {
        return CommonUtils.getUuid(holderBpn, StringUtils.join(request.getCredentialPayload().getDerive(), ""));
    }
}
