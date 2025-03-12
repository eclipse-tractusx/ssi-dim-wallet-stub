/*
 * *******************************************************************************
 *  Copyright (c) 2024 Contributors to the Eclipse Foundation
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

package org.eclipse.tractusx.wallet.stub.did;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;
import lombok.Getter;
import org.eclipse.edc.iam.did.spi.document.Service;
import org.eclipse.edc.iam.did.spi.document.VerificationMethod;

import java.util.ArrayList;
import java.util.List;

/**
 * When a DID URL gets resolved from ION, this object represents the JSON that is returned.
 */
@JsonDeserialize(builder = DidDocument.Builder.class)
@Getter
public class DidDocument {

    private final List<Service> service = new ArrayList<>();
    @JsonProperty("@context")
    private final List<Object> context = new ArrayList<>();
    private final List<VerificationMethod> verificationMethod = new ArrayList<>();
    private final List<String> authentication = new ArrayList<>();
    private String id;

    @Override
    public String toString() {
        return getId();
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static final class Builder {
        private final DidDocument document;

        private Builder() {
            document = new DidDocument();
        }

        @JsonCreator
        public static DidDocument.Builder newInstance() {
            return new Builder();
        }

        public Builder id(String id) {
            document.id = id;
            return this;
        }

        @JsonProperty("@context")
        public DidDocument.Builder context(List<Object> context) {
            document.context.addAll(context);
            return this;
        }

        public Builder service(List<Service> services) {
            document.service.addAll(services);
            return this;
        }

        public Builder verificationMethod(List<VerificationMethod> verificationMethod) {
            document.verificationMethod.addAll(verificationMethod);
            return this;
        }

        public Builder authentication(List<String> authentication) {
            document.authentication.addAll(authentication);
            return this;
        }

        public DidDocument build() {
            return document;
        }
    }
}
