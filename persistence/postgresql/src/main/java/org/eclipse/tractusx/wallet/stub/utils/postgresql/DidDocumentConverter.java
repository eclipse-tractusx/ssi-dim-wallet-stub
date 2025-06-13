/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
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

package org.eclipse.tractusx.wallet.stub.utils.postgresql;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;

import java.io.IOException;

import org.eclipse.tractusx.wallet.stub.did.api.DidDocument;

public class DidDocumentConverter implements AttributeConverter<DidDocument, String> {

    private static final ObjectMapper objectMapper = new ObjectMapper();


    @Override
    public String convertToDatabaseColumn(DidDocument didDocument) {
        try {
            return objectMapper.writeValueAsString(didDocument);
        } catch (IOException e) {
            throw new IllegalArgumentException("Error converting DidDocument to JSON", e);
        }
    }

    @Override
    public DidDocument convertToEntityAttribute(String json) {
        try {
            return objectMapper.readValue(json, DidDocument.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Error converting JSON to DidDocument", e);
        }
    }
}
