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

package org.eclipse.tractusx.wallet.stub.runtime.postgresql;

import org.eclipse.tractusx.wallet.stub.config.impl.WalletStubImplConfig;
import org.eclipse.tractusx.wallet.stub.config.postgresql.WalletStubStoragePostgresqlConfig;
import org.eclipse.tractusx.wallet.stub.config.rest.api.OpenApiConfig;
import org.eclipse.tractusx.wallet.stub.config.rest.service.ApplicationConfig;
import org.eclipse.tractusx.wallet.stub.config.rest.service.WalletStubRestServiceConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * The type Wallet demo application.
 */
@SpringBootApplication
@Import({WalletStubImplConfig.class,
        WalletStubStoragePostgresqlConfig.class,
        OpenApiConfig.class,
        ApplicationConfig.class,
        WalletStubRestServiceConfig.class
})
@EnableAsync
public class WalletStubApplication {

    /**
     * The entry point of application.
     *
     * @param args the input arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(WalletStubApplication.class, args);
    }

}
