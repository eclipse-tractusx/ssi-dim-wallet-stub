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

package org.eclipse.tractusx.wallet.stub.utils;


import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringEscapeUtils;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


@Slf4j
@UtilityClass
public class DeterministicECKeyPairGenerator {


    /**
     * Generates a KeyPair based on a provided business partner number (bpn) and environment (env).
     *
     * @param bpn the business partner number
     * @param env the environment
     * @return a KeyPair containing the generated EC private and public keys
     */
    @SneakyThrows
    public static KeyPair createKeyPair(String bpn, String env) {

        String randomString = bpn + "_" + env;

        // Step 1: Hash the identification
        byte[] seed = hashIdentification(randomString);

        // Step 2: Seed the SecureRandom instance
        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        secureRandom.setSeed(seed);

        // Step 3: Generate the EC key pair
        KeyPair keyPair = generateECKeyPair(secureRandom);


        log.debug("Keypair is generated for bpn -> {}", StringEscapeUtils.escapeJava(bpn));

        return keyPair;
    }


    private static byte[] hashIdentification(String identification) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(identification.getBytes());
    }

    @SneakyThrows
    private static KeyPair generateECKeyPair(SecureRandom secureRandom) {
        return new ECKeyGenerator(Curve.SECP256K1)
                .secureRandom(secureRandom)
                .provider(BouncyCastleProviderSingleton.getInstance())
                .generate().toKeyPair();
    }
}
