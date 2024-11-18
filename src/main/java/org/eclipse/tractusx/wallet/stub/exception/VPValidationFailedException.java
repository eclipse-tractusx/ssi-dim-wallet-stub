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

package org.eclipse.tractusx.wallet.stub.exception;

/**
 * Custom exception class to represent a failed validation of a Verifiable Presentation (VP).
 * This exception is thrown when a validation check fails during the processing of a VP.
 *
 * @author Cofinity-X Contributors
 * @since 1.0.0
 */
public class VPValidationFailedException extends RuntimeException {

    /**
     * Constructs a new VPValidationFailedException with the specified detail message.
     *
     * @param message the detail message (which is saved for later retrieval by the {@link #getMessage()} method)
     */
    public VPValidationFailedException(String message) {
        super(message);
    }
}
