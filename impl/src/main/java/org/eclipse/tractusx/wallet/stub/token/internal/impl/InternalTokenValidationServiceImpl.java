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

package org.eclipse.tractusx.wallet.stub.token.internal.impl;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.ParseStubException;
import org.eclipse.tractusx.wallet.stub.key.api.KeyService;
import org.eclipse.tractusx.wallet.stub.token.internal.api.InternalTokenValidationService;
import org.eclipse.tractusx.wallet.stub.utils.impl.CommonUtils;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;

@Service
@Slf4j
@RequiredArgsConstructor
public class InternalTokenValidationServiceImpl implements InternalTokenValidationService {

    private final KeyService keyService;

    @Override
    public boolean verifyToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(CommonUtils.cleanToken(token));
            String keyID = signedJWT.getHeader().getKeyID(); //this will be DID
            String bpn = CommonUtils.getBpnFromDid(keyID);
            KeyPair keyPair = keyService.getKeyPair(bpn);
            ECPublicKey aPublic = (ECPublicKey) keyPair.getPublic();
            ECDSAVerifier ecdsaVerifier = new ECDSAVerifier(aPublic);
            ecdsaVerifier.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
            return signedJWT.verify(ecdsaVerifier);
        } catch (InternalErrorException e) {
            throw e;
        } catch (ParseException e) {
            throw new ParseStubException(e.getMessage());
        } catch (Exception e) {
            throw new InternalErrorException("Internal Error: " + e.getMessage());
        }
    }
}
