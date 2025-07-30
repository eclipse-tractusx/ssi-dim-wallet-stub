/*
 * *******************************************************************************
 *  Copyright (c) 2025 LKS Next
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
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 * ******************************************************************************
 */

package org.eclipse.tractusx.wallet.stub.credential.impl;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.credential.api.CredentialService;
import org.eclipse.tractusx.wallet.stub.credential.impl.internal.api.InternalCredentialService;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.api.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.api.Storage;
import org.eclipse.tractusx.wallet.stub.token.impl.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.api.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.security.KeyPair;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialServiceImpl implements CredentialService, InternalCredentialService {


    private final Storage storage;

    private final KeyService keyService;

    private final DidDocumentService didDocumentService;

    private final WalletStubSettings walletStubSettings;

    private final TokenSettings tokenSettings;


    @Override
    public Pair<String, String> getVerifiableCredentialByHolderBpnAndTypeAsJwt(String holderBpn, String type) {
        try {
            Optional<Pair<String, String>> optionalVC = storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type);
            if (optionalVC.isPresent()) {
                //if Id is URI, we need to extract the id part
                String vcId = optionalVC.get().getLeft();
                if(vcId.contains("#")){
                    String[] parts = vcId.split("#");
                    if (parts.length > 1) {
                        vcId = parts[1];
                    }
                }
                return Pair.of(vcId, optionalVC.get().getRight());
            }

            CustomCredential verifiableCredential = getVerifiableCredentialByHolderBpnAndType(holderBpn, type);
            KeyPair issuerKeyPair = keyService.getKeyPair(walletStubSettings.baseWalletBPN());
            DidDocument issuerDocument = didDocumentService.getOrCreateDidDocument(walletStubSettings.baseWalletBPN());
            DidDocument holderDocument = didDocumentService.getOrCreateDidDocument(holderBpn);

            //time config
            Date time = new Date();
            Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

            //claims
            JWTClaimsSet tokenBody = new JWTClaimsSet.Builder()
                    .issueTime(time)
                    .jwtID(UUID.randomUUID().toString())
                    .audience(List.of(issuerDocument.getId(), holderDocument.getId()))
                    .expirationTime(expiryTime)
                    .claim(Constants.BPN, holderBpn)
                    .claim(Constants.VC, verifiableCredential)
                    .issuer(issuerDocument.getId())
                    .subject(issuerDocument.getId())
                    .build();

            SignedJWT vcJWT = CommonUtils.signedJWT(tokenBody, issuerKeyPair, issuerDocument.getVerificationMethod().getFirst().getId());

            String vcAsJwt = vcJWT.serialize();
            String vcIdUri = verifiableCredential.get(Constants.ID).toString();
            storage.saveCredentialAsJwt(vcIdUri, vcAsJwt, holderBpn, type);
            return Pair.of(vcIdUri.split("#")[1] ,vcAsJwt);
        } catch (IllegalArgumentException | InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    /**
     * Retrieves a verifiable credential based on the specified holder's BPN and type.
     * If the credential already exists in memory, it is returned directly.
     * If not, a new verifiable credential is issued and returned.
     *
     * @param holderBpn The BPN of the holder for whom the credential is issued.
     * @param type      The type of the credential.
     * @return The verifiable credential for the specified holder's BPN and type.
     */
    @Override
    public CustomCredential getVerifiableCredentialByHolderBpnAndType(String holderBpn, String type) {
        try {
            Optional<CustomCredential> verifiableCredentialOptional = storage.getCredentialsByHolderBpnAndType(holderBpn, type);
            if (verifiableCredentialOptional.isPresent()) {
                return verifiableCredentialOptional.get();
            } else {
                //issue new VC of that type of
                DidDocument issuerDocument = didDocumentService.getOrCreateDidDocument(walletStubSettings.baseWalletBPN());
                DidDocument holderDocument = didDocumentService.getOrCreateDidDocument(holderBpn);
                //build VC without a proof
                String vcId = CommonUtils.getUuid(holderBpn, type);
                URI vcIdUri = URI.create(issuerDocument.getId() + Constants.HASH_SEPARATOR + vcId);

                if (type.equals(Constants.MEMBERSHIP_CREDENTIAL)) {
                    return issueMembershipCredential(holderBpn, issuerDocument, holderDocument, vcIdUri, vcId);
                } else if (type.equals(Constants.BPN_CREDENTIAL)) {
                    return issueBpnCredential(holderBpn, issuerDocument, holderDocument, vcIdUri, vcId);
                } else if (type.equals(Constants.DATA_EXCHANGE_CREDENTIAL)) {
                    return issueDataExchangeGovernanceCredential(holderBpn, issuerDocument, holderDocument, vcIdUri, vcId);
                } else if (type.equals(Constants.USAGE_PURPOSE_CREDENTIAL)) {
                    return issueUsagePurposeCredential(holderBpn, issuerDocument, holderDocument, vcIdUri, vcId);
                } else {
                    throw new IllegalArgumentException("vc type -> " + type + " is not supported");
                }
            }
        } catch (IllegalArgumentException | InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    @Override
    public CustomCredential issueStatusListCredential(String holderBpn, String vcId) {
        try {
            DidDocument issuerDocument = didDocumentService.getOrCreateDidDocument(walletStubSettings.baseWalletBPN());

            URI vcIdUri = URI.create(issuerDocument.getId() + Constants.HASH_SEPARATOR + vcId);

            Map<String, Object> subject = new HashMap<>();
            subject.put(Constants.TYPE, Constants.STATUS_LIST_2021_CREDENTIAL);
            subject.put(Constants.ENCODED_LIST, CommonUtils.getEncodedList());
            subject.put(Constants.STATUS_PURPOSE, Constants.REVOCATION);

            CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                    vcIdUri.toString(), Constants.STATUS_LIST_2021_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);


            storage.saveCredentials(vcIdUri.toString(), credentialWithoutProof, holderBpn, Constants.STATUS_LIST_2021_CREDENTIAL);
            return credentialWithoutProof;
        } catch (InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private CustomCredential issueMembershipCredential(String holderBpn, DidDocument issuerDocument, DidDocument holderDocument, URI vcIdUri, String vcId) {
        try {
            Map<String, Object> subject = new HashMap<>();
            subject.put(Constants.ID, holderDocument.getId());
            subject.put(Constants.HOLDER_IDENTIFIER, holderBpn);
            subject.put(Constants.MEMBER_OF, "Catena-X");
            CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                    vcIdUri.toString(), Constants.MEMBERSHIP_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);
            storage.saveCredentials(vcIdUri.toString(), credentialWithoutProof, holderBpn, Constants.MEMBERSHIP_CREDENTIAL);
            return credentialWithoutProof;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private CustomCredential issueBpnCredential(String holderBpn, DidDocument issuerDocument, DidDocument holderDocument, URI vcIdUri, String vcId) {
        try {
            Map<String, Object> subject = new HashMap<>();
            subject.put(Constants.ID, holderDocument.getId());
            subject.put(Constants.HOLDER_IDENTIFIER, holderBpn);
            subject.put(Constants.BPN, holderBpn);
            CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                    vcIdUri.toString(), Constants.BPN_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);

            storage.saveCredentials(vcIdUri.toString(), credentialWithoutProof, holderBpn, Constants.BPN_CREDENTIAL);
            return credentialWithoutProof;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }

    private CustomCredential issueUsagePurposeCredential(String holderBpn, DidDocument issuerDocument, DidDocument holderDocument, URI vcIdUri, String vcId) {
        Map<String, Object> subject = new HashMap<>();
        subject.put(Constants.ID, holderDocument.getId());
        subject.put(Constants.HOLDER_IDENTIFIER, holderBpn);
        // here does this specification for group and UC come from?
        // subject.put(StringPool.GROUP, "UseCaseFramework");
        // subject.put(StringPool.USE_CASE, "DataExchangeGovernance");
        // subject.put(StringPool.CONTRACT_TEMPLATE, "https://example.org/temp-1");
        // subject.put(StringPool.CONTRACT_VERSION, "1.0");
        CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                vcIdUri.toString(), Constants.USAGE_PURPOSE_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);

        storage.saveCredentials(vcIdUri.toString(), credentialWithoutProof, holderBpn, Constants.USAGE_PURPOSE_CREDENTIAL);
        return credentialWithoutProof;
    }

    private CustomCredential issueDataExchangeGovernanceCredential(String holderBpn, DidDocument issuerDocument, DidDocument holderDocument, URI vcIdUri, String vcId) {
        try {
            Map<String, Object> subject = new HashMap<>();
            subject.put(Constants.ID, holderDocument.getId());
            subject.put(Constants.HOLDER_IDENTIFIER, holderBpn);
            subject.put(Constants.GROUP, "UseCaseFramework");
            subject.put(Constants.USE_CASE, "DataExchangeGovernance");
            subject.put(Constants.CONTRACT_TEMPLATE, "https://example.org/temp-1");
            subject.put(Constants.CONTRACT_VERSION, "1.0");
            CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                    vcIdUri.toString(), Constants.DATA_EXCHANGE_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);

            storage.saveCredentials(vcIdUri.toString(), credentialWithoutProof, holderBpn, Constants.DATA_EXCHANGE_CREDENTIAL);
            return credentialWithoutProof;
        } catch (IllegalArgumentException | InternalErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }
}
