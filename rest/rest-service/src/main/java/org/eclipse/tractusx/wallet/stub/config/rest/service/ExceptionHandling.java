/*
 * *******************************************************************************
 *  Copyright (c) 2025 Contributors to the Eclipse Foundation
 *  Copyright (c) 2025 Cofinity-X
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

package org.eclipse.tractusx.wallet.stub.config.rest.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.eclipse.tractusx.wallet.stub.exception.api.CredentialNotFoundException;
import org.eclipse.tractusx.wallet.stub.exception.api.InternalErrorException;
import org.eclipse.tractusx.wallet.stub.exception.api.MalformedCredentialsException;
import org.eclipse.tractusx.wallet.stub.exception.api.NoStatusListFoundException;
import org.eclipse.tractusx.wallet.stub.exception.api.NoVCTypeFoundException;
import org.eclipse.tractusx.wallet.stub.exception.api.ParseStubException;
import org.eclipse.tractusx.wallet.stub.exception.api.VPValidationFailedException;
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
        log.error(errorMsg, e);
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
        log.error(errorMsg, e);
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
        log.error(errorMsg, e);
        return problemDetail;
    }

    /**
     * Handles ParseStubException by creating a ProblemDetail object.
     * This method is used to handle exceptions thrown when a string or data segment cannot be parsed into the expected format
     *
     * @param e The ParseStubException that occurred. This exception typically indicates that parsing input according to an expected format or syntax failed.
     * @return A ProblemDetail object containing information about the exception. The ProblemDetail object includes
     * the HTTP status code (400 BAD REQUEST), a description of the error, and a timestamp indicating when the error occurred.
     */
    @ExceptionHandler(ParseStubException.class)
    ProblemDetail handleParseStubException(ParseStubException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, errorMsg);
        problemDetail.setTitle(e.getMessage());
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.error(errorMsg, e);
        return problemDetail;
    }

    /**
     * Handles CredentialNotFoundException by creating a ProblemDetail object.
     * This method is used to handle exceptions thrown when the system attempts to retrieve or look up credentials
     * (e.g., based on a user identifier, client ID, or presented token) but they cannot be found in the underlying storage or identity system.
     *
     * @param e The CredentialNotFoundException that occurred. This exception indicates that the requested or specified credentials do not exist or could not be located.
     * @return A ProblemDetail object containing information about the exception. The ProblemDetail object includes
     * the HTTP status code (404 NOT_FOUND), a description of the error, and a timestamp indicating when the error occurred.
     */
    @ExceptionHandler(CredentialNotFoundException.class)
    ProblemDetail handleCredentialNotFoundException(CredentialNotFoundException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, errorMsg);
        problemDetail.setTitle("Not Found: " + e.getMessage());
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.error(errorMsg, e);
        return problemDetail;
    }

    /**
     * Handles NoStatusListFoundException by creating a ProblemDetail object.
     * This method is used to handle exceptions thrown when the system attempts to retrieve or look up statusList
     * by BPN but they cannot be found in the underlying storage or identity system.
     *
     * @param e The NoStatusListFoundException that occurred. This exception indicates that the requested or specified statusList do not exist or could not be located.
     * @return A ProblemDetail object containing information about the exception. The ProblemDetail object includes
     * the HTTP status code (404 NOT_FOUND), a description of the error, and a timestamp indicating when the error occurred.
     */
    @ExceptionHandler(NoStatusListFoundException.class)
    ProblemDetail handleNoStatusListFoundException(NoStatusListFoundException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, errorMsg);
        problemDetail.setTitle("Not Found: " + e.getMessage());
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.error(errorMsg, e);
        return problemDetail;
    }

    /**
     * Handles MalformedCredentialsException by creating a ProblemDetail object.
     * This method is used to handle exceptions thrown when provided credentials (e.g., within an Authorization header or request body)
     * are syntactically incorrect, cannot be decoded, or are otherwise structurally invalid. It indicates the server understands the request content type
     * but cannot process the contained credentials due to format issues.
     *
     * @param e The MalformedCredentialsException that occurred. This exception indicates that the format or structure of the supplied credentials is invalid.
     * @return A ProblemDetail object containing information about the exception. The ProblemDetail object includes
     * the HTTP status code (422 UNPROCESSABLE_ENTITY), a description of the error, and a timestamp indicating when the error occurred.
     */
    @ExceptionHandler(MalformedCredentialsException.class)
    ProblemDetail handleMalformedCredentialsException(MalformedCredentialsException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNPROCESSABLE_ENTITY, errorMsg);
        problemDetail.setTitle("Unprocessable Entity: " + e.getMessage());
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.error(errorMsg, e);
        return problemDetail;
    }

    /**
     * Handles NoVCTypeFoundException by creating a ProblemDetail object.
     * * This method is invoked when processing a Verifiable Credential (VC) where the 'type' array does not contain exactly one or two elements.
     *
     * @param e The NoVCTypeFoundException that occurred. This exception signals that necessary type information could not be found within a Verifiable Credential.
     * @return A ProblemDetail object containing information about the exception. The ProblemDetail object includes
     * the HTTP status code (422 UNPROCESSABLE_ENTITY), a description of the error, and a timestamp indicating when the error occurred.
     */
    @ExceptionHandler(NoVCTypeFoundException.class)
    ProblemDetail handleNoVCTypeFoundException(NoVCTypeFoundException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.UNPROCESSABLE_ENTITY, errorMsg);
        problemDetail.setTitle("Unprocessable Entity: " + e.getMessage());
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.error(errorMsg, e);
        return problemDetail;
    }

    /**
     * Handles InternalErrorException by creating a ProblemDetail object.
     * This method is used to handle exceptions representing unexpected internal server errors that occurred during request processing.
     * These are typically errors not directly caused by invalid client input but by issues within the server's logic, state, or dependencies.
     *
     * @param e The InternalErrorException that occurred. This exception signals an unexpected condition or failure within the server application.
     * @return A ProblemDetail object containing information about the exception. The ProblemDetail object includes
     * the HTTP status code (500 INTERNAL_SERVER_ERROR), a description of the error, and a timestamp indicating when the error occurred.
     */
    @ExceptionHandler(InternalErrorException.class)
    ProblemDetail handleInternalErrorException(InternalErrorException e) {
        String errorMsg = ExceptionUtils.getMessage(e);
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, errorMsg);
        problemDetail.setTitle("Internal Server Error");
        problemDetail.setProperty(TIMESTAMP, System.currentTimeMillis());
        log.error(errorMsg, e);
        return problemDetail;
    }
}
