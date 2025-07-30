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

package storage.memory;

import org.eclipse.tractusx.wallet.stub.storage.memory.MemoryStorage;
import org.eclipse.tractusx.wallet.stub.utils.api.Constants;
import org.eclipse.tractusx.wallet.stub.utils.api.CustomCredential;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class MemoryStorageTest {

    @Test
    void getVcIdAndTypesByHolderBpn_shouldReturnMatchingCredentials() {
        // Arrange
        MemoryStorage storage = new MemoryStorage();
        String holderBpn = "BPNL000000000001";
        String type = "TestCredential";
        String type1 = "TestCredential1";

        // Create test credentials
        CustomCredential matchingCredential = new CustomCredential();
        matchingCredential.put(Constants.TYPE, List.of("VerifiableCredential", type));
        matchingCredential.put(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE, Map.of("id", "did:web:test:" + holderBpn));

        CustomCredential nonMatchingCredential = new CustomCredential();
        nonMatchingCredential.put(Constants.TYPE, List.of("VerifiableCredential", type));
        nonMatchingCredential.put(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE, Map.of("id", "did:web:test:BPNL000000000002"));

        CustomCredential invalidCredential = new CustomCredential();
        invalidCredential.put(Constants.TYPE, List.of("VerifiableCredential", type));
        invalidCredential.put(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE, Map.of("someOtherId", "value"));

        // Store credentials
        storage.saveCredentials("vc1", matchingCredential, holderBpn, type);
        storage.saveCredentials("vc2", nonMatchingCredential, "BPNL000000000002", type);
        storage.saveCredentials("vc3", invalidCredential, holderBpn, type1);

        // Act
        List<CustomCredential> result = storage.getVcIdAndTypesByHolderBpn(holderBpn);

        // Assert
        assertNotNull(result);
        assertEquals(1, result.size());
        CustomCredential retrievedCredential = result.get(0);
        assertEquals(matchingCredential, retrievedCredential);
        assertEquals("did:web:test:" + holderBpn,
                ((Map<String, String>)retrievedCredential.get(Constants.CREDENTIAL_SUBJECT_CAMEL_CASE)).get(Constants.ID));
    }
}
