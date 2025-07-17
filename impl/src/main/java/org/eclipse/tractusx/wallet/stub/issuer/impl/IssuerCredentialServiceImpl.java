/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
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
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.CredentialNotFoundException;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.NoVCTypeFoundException;
import org.eclipse.tractusx.wallet.stub.exception.api.ParseStubException;
import org.eclipse.tractusx.wallet.stub.issuer.api.IssuerCredentialService;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.CredentialsSupported;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.GetCredentialsResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssueCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.IssuerMetadataResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.MatchingCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredential;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.RequestedCredentialStatusResponse;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialRequest;
import org.eclipse.tractusx.wallet.stub.issuer.api.dto.SignCredentialResponse;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.api.TokenService;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class IssuerCredentialServiceImpl implements IssuerCredentialService {

    private final WalletStubSettings walletStubSettings;

    private final KeyService keyService;
    private final DidDocumentService didDocumentService;
    private final Storage storage;
    private final TokenService tokenService;
    private final TokenSettings tokenSettings;
    private final CredentialService credentialService;


    @SuppressWarnings("unchecked")
    private static String getHolderBpn(CustomCredential verifiableCredential) {
        try {
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
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
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
    private Map<String, String> issueCredential(IssueCredentialRequest request, String issuerBPN) {
        try {
            KeyPair issuerKeypair = keyService.getKeyPair(walletStubSettings.baseWalletBPN());

            DidDocument issuerDidDocument = didDocumentService.getOrCreateDidDocument(issuerBPN);

            CustomCredential verifiableCredential = new CustomCredential();

            //we have two options here, user can ask only to provide VC ID or JWT and VC ID
            if (!CollectionUtils.isEmpty(request.getCredentialPayload().getIssue())) {
                verifiableCredential.putAll(request.getCredentialPayload().getIssue());
            } else {
                verifiableCredential.putAll((Map<String, Object>) request.getCredentialPayload().getIssueWithSignature().get(Constants.CONTENT));
            }
            String holderBpn = getHolderBpn(verifiableCredential);

            DidDocument holderDidDocument = didDocumentService.getOrCreateDidDocument(holderBpn);

            String type = CommonUtils.getTypeFromCustomCredential(verifiableCredential);

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
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }


    private Optional<String> signCredential(String credentialId) {
        try {
            DidDocument issuerDidDocument = didDocumentService.getOrCreateDidDocument(walletStubSettings.baseWalletBPN());
            URI vcIdUri = URI.create(issuerDidDocument.getId() + Constants.HASH_SEPARATOR + credentialId);
            return storage.getCredentialAsJwt(vcIdUri.toString());
        } catch (InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public GetCredentialsResponse getCredential(String externalCredentialId) {
        try {
            DidDocument issuerDidDocument = didDocumentService.getOrCreateDidDocument(walletStubSettings.baseWalletBPN());
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
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private String storeCredential(IssueCredentialRequest request, String holderBpn) {
        try {
            return CommonUtils.getUuid(holderBpn, StringUtils.join(request.getCredentialPayload().getDerive(), ""));
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public SignCredentialResponse getSignCredentialResponse(SignCredentialRequest request, String credentialId) {
        try {
            if (Objects.nonNull(request.getPayload()) && request.getPayload().isRevoke()) {
                return null;
            } else {
                Optional<String> jwtVc = signCredential(credentialId);
                if (jwtVc.isPresent()) {
                    return new SignCredentialResponse(jwtVc.get());
                } else {
                    throw new CredentialNotFoundException("No credential found for credentialId -> " + credentialId);
                }
            }
        } catch (CredentialNotFoundException | InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public IssueCredentialResponse getIssueCredentialResponse(IssueCredentialRequest request, String token) {
        try {
            Validate.isTrue(request.isValid(), "Invalid request");

            String vcId;
            String jwt = null;
            if (Objects.nonNull(request.getCredentialPayload().getDerive())) {
                vcId = storeCredential(request, CommonUtils.getBpnFromToken(token, tokenService));
            } else {
                Map<String, String> map = issueCredential(request, CommonUtils.getBpnFromToken(token, tokenService));
                vcId = map.get(Constants.ID);
                jwt = map.get(Constants.JWT);
            }
            return IssueCredentialResponse.builder()
                    .id(vcId)
                    .jwt(jwt)
                    .build();
        } catch (ParseStubException | IllegalArgumentException | NoVCTypeFoundException | InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @SneakyThrows
    @Override
    public IssuerMetadataResponse getIssuerMetadata(String issuerId) {

        DidDocument issuerDidDocument = didDocumentService.getOrCreateDidDocument(issuerId);

        CredentialsSupported credentialsSupported = CredentialsSupported.builder()
                .type(Constants.CREDENTIAL_OBJECT)
                .profiles(Constants.CREDENTIAL_PROFILE)
                .offerReason(Constants.OFFER_REASON)
                .bindingMethods(List.of(Constants.DID_WEB))
                .credentialType(Constants.SUPPORTED_VC_TYPES)
                .issuancePolicy(Map.of())
                .build();
        return IssuerMetadataResponse.builder()
                .context(walletStubSettings.issuerMetadataContextUrls())
                .type(Constants.CREDENTIAL_ISSUER)
                .credentialIssuer(issuerDidDocument.getId())
                .credentialsSupported(List.of(credentialsSupported))
                .build();
    }

    @Override
    public IssueCredentialResponse requestCredentialFromIssuer(RequestCredential requestCredential, String applicationKey, String token) {

        //in the stub issuer we only support one requested credential
        if(requestCredential.getRequestedCredentials().size() !=1){
            throw new IllegalArgumentException("Only one requested credential is supported in the stub issuer");
        }

        //validate token
        String callerBpn = tokenService.verifyTokenAndGetClaims(token).getClaim(Constants.BPN).toString();
        if(!Objects.equals(callerBpn, walletStubSettings.baseWalletBPN())){
            throw new IllegalArgumentException("Caller BPN does not match the base wallet BPN");
        }

        String holderBpn = CommonUtils.getBpnFromDid(requestCredential.getHolderDid());

        //create did document if not exists
        didDocumentService.getOrCreateDidDocument(holderBpn);

        Pair<String, String> pair = credentialService.getVerifiableCredentialByHolderBpnAndTypeAsJwt(holderBpn, requestCredential.getRequestedCredentials().get(0).getCredentialType());
        return IssueCredentialResponse.builder()
                .id(pair.getLeft())
                .jwt(pair.getRight())
                .build();
    }

    @Override
    public RequestedCredentialStatusResponse getCredentialRequestStatus(String credentialRequestId, String token) {
        GetCredentialsResponse credential = getCredential(credentialRequestId);
        String type = ((List<String>) credential.getCredential().get(Constants.TYPE)).get(1);
        Map<String, String> credentialSubject = (Map<String, String>) credential.getCredential().get(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE);

        return RequestedCredentialStatusResponse.builder()
                .id(credentialRequestId)
                .expirationDate(credential.getCredential().get(Constants.EXPIRATION_DATE).toString())
                .issuerDid(credential.getCredential().get(Constants.ISSUER).toString())
                .holderDid(credentialSubject.get(Constants.ID))
                .requestedCredentials(List.of(RequestedCredential.builder()
                                .credentialType(type)
                                .format(Constants.VCDM_11_JWT)
                        .build())
                )
                .status(Constants.STATUS_ISSUED)
                .matchingCredentials(List.of(
                        MatchingCredential.builder()
                                .id(credentialRequestId)
                                .name(type)
                                .description(type)
                                .verifiableCredential(credential.getVerifiableCredential())
                                .credential(credential.getCredential())
                                .application(Constants.CATENA_X_PORTAL)
                                .build()
                ))
                .build();
    }

    @Override
    public RequestedCredentialResponse getRequestedCredential(String holderDid, String token) {
        String holderBpn = CommonUtils.getBpnFromDid(holderDid);
        List<CustomCredential> credentials = storage.getVcIdAndTypesByHolderBpn(holderBpn);

        List<RequestCredential> requestedCredentials = new ArrayList<>(credentials.size());

        credentials.forEach(credential ->{
            String vcId = credential.get(Constants.ID).toString().split("#")[1];
            requestedCredentials.add(RequestCredential.builder()
                            .id(vcId)
                            .issuerDid(credential.get(Constants.ISSUER).toString())
                            .holderDid(CommonUtils.getDidWeb(walletStubSettings.didHost(), holderBpn))
                            .expirationDate(credential.get(Constants.EXPIRATION_DATE).toString())
                            .deliveryStatus(Constants.DELIVERY_STATUS_COMPLETED)
                            .status(Constants.STATUS_ISSUED)
                            .approvedCredentials(List.of(vcId))
                            .requestedCredentials(List.of(
                                    RequestedCredential.builder()
                                            .credentialType(CommonUtils.getTypeFromCustomCredential(credential))
                                            .format(Constants.VCDM_11_JWT)
                                            .build()
                            ))

                    .build());
        });
        return RequestedCredentialResponse.builder()
                .count(credentials.size())
                .requestedCredentials(requestedCredentials)
                .build();
    }
}
