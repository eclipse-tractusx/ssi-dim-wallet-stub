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

package org.eclipse.tractusx.wallet.stub.config;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.tractusx.wallet.stub.portal.PortalStubService;
import org.eclipse.tractusx.wallet.stub.portal.dto.SetupDimRequest;
import org.eclipse.tractusx.wallet.stub.statuslist.StatusListCredentialService;
import org.eclipse.tractusx.wallet.stub.storage.Storage;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * The type Initial setup config class. It will create an Operator(base wallet) once the application is ready
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class InitialSetupConfig {

    private final Storage storage;

    private final PortalStubService portalStubService;

    private final WalletStubSettings walletStubSettings;

    private final StatusListCredentialService statusListCredentialService;


    /**
     * Sets up the base wallet by creating a DIM for a company and generating a status list Verifiable Credential.
     *
     * <p>This method is annotated with {@link EventListener} and listens for the {@link ApplicationReadyEvent}
     * to trigger the setup process.
     */
    @SneakyThrows
    @EventListener(ApplicationReadyEvent.class)
    public void setupBaseWallet() {
        if(storage.getDidDocument(walletStubSettings.baseWalletBPN()).isEmpty()){
            SetupDimRequest request = new SetupDimRequest();
            request.setBpn(walletStubSettings.baseWalletBPN());
            request.setCompanyName("Eclipse Tractus-x Operating Company");
            request.setDidDocumentLocation(walletStubSettings.didHost());

            //create did a document and lry pair
            portalStubService.setupDim(request);

            //create status list VC
            statusListCredentialService.getStatusListCredential(walletStubSettings.baseWalletBPN(), walletStubSettings.statusListVcId());

            //create wallets for the seeded BPNs specified in the configuration
            int cont = 1;
            for (String bpn: walletStubSettings.seedWalletsBPN()){
                SetupDimRequest seedRequest = new SetupDimRequest();
                seedRequest.setBpn(bpn);
                seedRequest.setCompanyName("Seed Wallet "+cont);
                seedRequest.setDidDocumentLocation(walletStubSettings.didHost());
                portalStubService.setupDim(seedRequest);
                statusListCredentialService.getStatusListCredential(bpn, walletStubSettings.statusListVcId());
                cont++;
            }

            log.debug("Base wallet with bpn is {} created and status list VC is also created", walletStubSettings.baseWalletBPN());
        }else {
            log.debug("Wallet is using persistent data.");
        }
    }
}
