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

package org.eclipse.tractusx.wallet.stub.credential;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.eclipse.tractusx.wallet.stub.config.WalletStubSettings;
import org.eclipse.tractusx.wallet.stub.did.DidDocument;
import org.eclipse.tractusx.wallet.stub.did.DidDocumentService;
import org.eclipse.tractusx.wallet.stub.key.KeyService;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.eclipse.tractusx.wallet.stub.token.TokenSettings;
import org.eclipse.tractusx.wallet.stub.utils.CommonUtils;
import org.eclipse.tractusx.wallet.stub.utils.CustomCredential;
import org.eclipse.tractusx.wallet.stub.utils.StringPool;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.security.KeyPair;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialServiceImpl implements CredentialService {


    private final Storage storage;

    private final KeyService keyService;

    private final DidDocumentService didDocumentService;


    private final WalletStubSettings walletStubSettings;

    private final TokenSettings tokenSettings;


    @SneakyThrows
    public String getVerifiableCredentialByHolderBpnAndTypeAsJwt(String holderBpn, String type) {

        Optional<String> optionalVC = storage.getCredentialsAsJwtByHolderBpnAndType(holderBpn, type);
        if (optionalVC.isPresent()) {
            return optionalVC.get();
        }

        CustomCredential verifiableCredential = getVerifiableCredentialByHolderBpnAndType(holderBpn, type);
        KeyPair issuerKeyPair = keyService.getKeyPair(walletStubSettings.baseWalletBPN());
        DidDocument issuerDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());
        DidDocument holderDocument = didDocumentService.getDidDocument(holderBpn);

        //time config
        Date time = new Date();
        Date expiryTime = DateUtils.addMinutes(time, tokenSettings.tokenExpiryTime());

        //claims
        JWTClaimsSet tokenBody = new JWTClaimsSet.Builder()
                .issueTime(time)
                .jwtID(UUID.randomUUID().toString())
                .audience(List.of(issuerDocument.getId(), holderDocument.getId()))
                .expirationTime(expiryTime)
                .claim(StringPool.BPN, holderBpn)
                .claim(StringPool.VC, verifiableCredential)
                .issuer(issuerDocument.getId())
                .subject(issuerDocument.getId())
                .build();

        SignedJWT vcJWT = CommonUtils.signedJWT(tokenBody, issuerKeyPair, issuerDocument.getVerificationMethod().getFirst().getId());

        String vcAsJwt = vcJWT.serialize();
        storage.saveCredentialAsJwt(verifiableCredential.get(StringPool.ID).toString(), vcAsJwt, holderBpn, type);
        return vcAsJwt;
    }

    @SneakyThrows
    public CustomCredential getVerifiableCredentialByHolderBpnAndType(String holderBpn, String type) {
        Optional<CustomCredential> verifiableCredentialOptional = storage.getCredentialsByHolderBpnAndType(holderBpn, type);
        if (verifiableCredentialOptional.isPresent()) {
            return verifiableCredentialOptional.get();
        } else {
            //issue new VC of that type of
            DidDocument issuerDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());
            DidDocument holderDocument = didDocumentService.getDidDocument(holderBpn);
            //build VC without a proof
            String vcId = CommonUtils.getUuid(holderBpn, type);
            URI vcIdUri = URI.create(issuerDocument.getId() + StringPool.HASH_SEPARATOR + vcId);

            if (type.equals(StringPool.MEMBERSHIP_CREDENTIAL)) {
                return issueMembershipCredential(holderBpn, issuerDocument, holderDocument, vcIdUri, vcId);
            } else if (type.equals(StringPool.BPN_CREDENTIAL)) {
                return issueBpnCredential(holderBpn, issuerDocument, holderDocument, vcIdUri, vcId);
            } else if (type.equals(StringPool.DATA_EXCHANGE_CREDENTIAL)) {
                return issueDataExchangeGovernanceCredential(holderBpn, issuerDocument, holderDocument, vcIdUri, vcId);
            } else {
                throw new IllegalArgumentException("vc type -> " + type + " is not supported");
            }
        }
    }


    public CustomCredential issueStatusListCredential(String holderBpn, String vcId) {
        DidDocument issuerDocument = didDocumentService.getDidDocument(walletStubSettings.baseWalletBPN());

        URI vcIdUri = URI.create(issuerDocument.getId() + StringPool.HASH_SEPARATOR + vcId);

        Map<String, Object> subject = new HashMap<>();
        subject.put(StringPool.TYPE, StringPool.STATUS_LIST_2021_CREDENTIAL);
        subject.put(StringPool.ENCODED_LIST, CommonUtils.getEncodedList());
        subject.put(StringPool.STATUS_PURPOSE, StringPool.REVOCATION);

        CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                vcIdUri.toString(), StringPool.STATUS_LIST_2021_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);


        storage.saveCredentials(vcIdUri.toString(), credentialWithoutProof, holderBpn, StringPool.STATUS_LIST_2021_CREDENTIAL);
        return credentialWithoutProof;
    }

    private CustomCredential issueMembershipCredential(String holderBpn, DidDocument issuerDocument, DidDocument holderDocument, URI vcIdUri, String vcId) {
        Map<String, Object> subject = new HashMap<>();
        subject.put(StringPool.ID, holderDocument.getId());
        subject.put(StringPool.HOLDER_IDENTIFIER, holderBpn);
        subject.put(StringPool.MEMBER_OF, "Catena-X");
        CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                vcIdUri.toString(), StringPool.MEMBERSHIP_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);
        storage.saveCredentials(vcId, credentialWithoutProof, holderBpn, StringPool.MEMBERSHIP_CREDENTIAL);
        return credentialWithoutProof;
    }

    private CustomCredential issueBpnCredential(String holderBpn, DidDocument issuerDocument, DidDocument holderDocument, URI vcIdUri, String vcId) {
        Map<String, Object> subject = new HashMap<>();
        subject.put(StringPool.ID, holderDocument.getId());
        subject.put(StringPool.HOLDER_IDENTIFIER, holderBpn);
        subject.put(StringPool.BPN, holderBpn);
        CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                vcIdUri.toString(), StringPool.BPN_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);

        storage.saveCredentials(vcId, credentialWithoutProof, holderBpn, StringPool.BPN_CREDENTIAL);
        return credentialWithoutProof;
    }

    private CustomCredential issueDataExchangeGovernanceCredential(String holderBpn, DidDocument issuerDocument, DidDocument holderDocument, URI vcIdUri, String vcId) {
        Map<String, Object> subject = new HashMap<>();
        subject.put(StringPool.ID, holderDocument.getId());
        subject.put(StringPool.HOLDER_IDENTIFIER, holderBpn);
        subject.put(StringPool.GROUP, "UseCaseFramework");
        subject.put(StringPool.USE_CASE, "DataExchangeGovernance");
        subject.put(StringPool.CONTRACT_TEMPLATE, "https://example.org/temp-1");
        subject.put(StringPool.CONTRACT_VERSION, "1.0");
        CustomCredential credentialWithoutProof = CommonUtils.createCredential(issuerDocument.getId(),
                vcIdUri.toString(), StringPool.DATA_EXCHANGE_CREDENTIAL, DateUtils.addYears(new Date(), 1), subject);

        storage.saveCredentials(vcId, credentialWithoutProof, holderBpn, StringPool.DATA_EXCHANGE_CREDENTIAL);
        return credentialWithoutProof;
    }
}
