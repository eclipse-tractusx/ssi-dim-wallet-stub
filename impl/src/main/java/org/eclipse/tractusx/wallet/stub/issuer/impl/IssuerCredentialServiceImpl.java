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

package org.eclipse.tractusx.wallet.stub.issuer.impl;

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
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.CredentialNotFoundException;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.NoVCTypeFoundException;
import org.eclipse.tractusx.wallet.stub.issuer.api.IssuerCredentialService;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.common.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class IssuerCredentialServiceImpl implements IssuerCredentialService{

    private final WalletStubSettings walletStubSettings;

    private final KeyService keyService;
    private final DidDocumentService didDocumentService;
    private final Storage storage;
    private final TokenSettings tokenSettings;

    @SuppressWarnings("unchecked")
    private static String getHolderBpn(CustomCredential verifiableCredential) {
        try{
            //get Holder BPN
            Map<String, Object> subject = (Map<String, Object>) verifiableCredential.get("credentialSubject");
            if (subject.containsKey(Constants.BPN)) {
                return subject.get(Constants.BPN).toString();
            } else if (subject.containsKey(Constants.HOLDER_IDENTIFIER)) {
                return subject.get(Constants.HOLDER_IDENTIFIER).toString();
            } else {
                throw new IllegalArgumentException("Can not identify holder BPN from VC");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e){
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    @SneakyThrows
    public Map<String, String> issueCredential(IssueCredentialRequest request, String issuerBPN) {
        try{
            KeyPair issuerKeypair = keyService.getKeyPair(walletStubSettings.baseWalletBPN());

            DidDocument issuerDidDocument = didDocumentService.getDidDocument(issuerBPN);

            CustomCredential verifiableCredential = new CustomCredential();

            //we have two options here, user can ask only to provide VC ID or JWT and VC ID
            if (!CollectionUtils.isEmpty(request.getCredentialPayload().getIssue())) {
                verifiableCredential.putAll(request.getCredentialPayload().getIssue());
            } else {
                verifiableCredential.putAll((Map<String, Object>) request.getCredentialPayload().getIssueWithSignature().get(Constants.CONTENT));
            }
            String holderBpn = getHolderBpn(verifiableCredential);

            DidDocument holderDidDocument = didDocumentService.getDidDocument(holderBpn);

            String type;
            List<String> types = (List<String>) verifiableCredential.get(Constants.TYPE);
            //https://www.w3.org/TR/vc-data-model/#types As per the VC schema, types can be multiple, but index 1 should have the correct type.
            if (types.size() == 2) {
                type = types.get(1);
            } else if (types.size() == 1) {
                type = types.getFirst();
            } else {
                throw new NoVCTypeFoundException("No type found in VC");
            }

            //sign
            String vcId = CommonUtils.getUuid(holderBpn, type);
            URI vcIdUri = URI.create(issuerDidDocument.getId() + Constants.HASH_SEPARATOR + vcId);
            URI issuer = new URI("did:web:" + walletStubSettings.didHost() + ":" + walletStubSettings.baseWalletBPN());

            verifiableCredential.put(Constants.ID, vcIdUri.toString());
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
                    .claim(Constants.BPN, holderBpn)
                    .claim(Constants.VC, verifiableCredential)
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
                return Map.of(Constants.ID, vcId, Constants.JWT, vcAsJwt);
            } else {
                return Map.of(Constants.ID, vcId);
            }
        } catch (IllegalArgumentException | NoVCTypeFoundException | InternalErrorException e) {
            throw e;
        } catch (Exception e){
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @SneakyThrows
    public Optional<String> signCredential(String credentialId) {
        try{
            DidDocument issuerDidDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());
            URI vcIdUri = URI.create(issuerDidDocument.getId() + Constants.HASH_SEPARATOR + credentialId);
            return storage.getCredentialAsJwt(vcIdUri.toString());
        } catch (InternalErrorException e) {
            throw e;
        } catch (Exception e){
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @SneakyThrows
    public GetCredentialsResponse getCredential(String externalCredentialId) {
        try{
            DidDocument issuerDidDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());
            URI vcIdUri = URI.create(issuerDidDocument.getId() + Constants.HASH_SEPARATOR + externalCredentialId);
            Optional<String> jwtVc = storage.getCredentialAsJwt(vcIdUri.toString());
            if (jwtVc.isEmpty()) {
                throw new CredentialNotFoundException("No credential found for credentialId -> " + externalCredentialId);
            }
            Optional<CustomCredential> optionalCustomVerifiableCredential = storage.getVerifiableCredentials(vcIdUri.toString());

            if (optionalCustomVerifiableCredential.isEmpty()) {
                throw new CredentialNotFoundException("No credential found for credentialId -> " + externalCredentialId);
            }
            return GetCredentialsResponse.builder()
                    .signingKeyId(issuerDidDocument.getVerificationMethod().getFirst().getId())
                    .revocationStatus("false")
                    .verifiableCredential(jwtVc.get())
                    .credential(optionalCustomVerifiableCredential.get())
                    .build();
        } catch (CredentialNotFoundException | InternalErrorException e) {
            throw e;
        } catch (Exception e){
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    public String storeCredential(IssueCredentialRequest request, String holderBpn) {
        try{
            return CommonUtils.getUuid(holderBpn, StringUtils.join(request.getCredentialPayload().getDerive(), ""));
        } catch (Exception e){
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }
}
