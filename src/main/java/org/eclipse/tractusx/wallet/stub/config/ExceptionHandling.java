/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
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

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.eclipse.tractusx.wallet.stub.exception.VPValidationFailedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * The type Exception handling.
 */
@RestControllerAdvice
@Slf4j
public class ExceptionHandling {

    /**
     * The constant TIMESTAMP.
     */
    public static final String TIMESTAMP = "timestamp";


    /**
     * Handles the {@link VPValidationFailedException} by creating a {@link ProblemDetail} object.
     * This method is used to handle exceptions thrown when a verifiable presentation fails validation.
     *
     * @param e The {@link VPValidationFailedException} that occurred.
     * @return A {@link ProblemDetail} object containing information about the exception.
     */
    @ExceptionHandler(VPValidationFailedException.class)
    ProblemDetail handleVPValidationFailedException(VPValidationFailedException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, errorMsg);
        problemDetail.setTitle("Invalid Verifiable Presentation");
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.debug(errorMsg);
        return problemDetail;
    }

    /**
     * Handles the {@link MissingRequestHeaderException} by creating a {@link ProblemDetail} object.
     * This method is used to handle exceptions thrown when a required HTTP header is missing.
     *
     * @param e The {@link MissingRequestHeaderException} that occurred. This exception is thrown when a required HTTP header is missing.
     * @return A {@link ProblemDetail} object containing information about the exception. The {@link ProblemDetail} object includes
     * the HTTP status code (401 UNAUTHORIZED), a brief description of the error, and a timestamp indicating when the error occurred.
     * The error title is set to "Please provide the required header: {headerName}", where {headerName} is the name of the missing header.
     */
    @ExceptionHandler(MissingRequestHeaderException.class)
    ProblemDetail handleMissingRequestHeaderException(MissingRequestHeaderException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, errorMsg);
        problemDetail.setTitle("Please provide the required header: " + e.getHeaderName());
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.debug(errorMsg);
        return problemDetail;
    }

    /**
     * Handles IllegalArgumentException by creating a ProblemDetail object.
     * This method is used to handle exceptions thrown when an illegal or inappropriate argument is passed to a method.
     *
     * @param e The IllegalArgumentException that occurred. This exception is thrown to indicate that a method has been passed an illegal or inappropriate argument.
     * @return A ProblemDetail object containing information about the exception. The ProblemDetail object includes
     * the HTTP status code (400 BAD REQUEST), a description of the error, and a timestamp indicating when the error occurred.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail handleIllegalException(IllegalArgumentException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, errorMsg);
        problemDetail.setTitle("Bad request: " + e.getMessage());
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.debug(errorMsg);
        return problemDetail;
    }
}
