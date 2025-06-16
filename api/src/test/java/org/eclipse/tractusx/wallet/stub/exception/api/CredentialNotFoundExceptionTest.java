package org.eclipse.tractusx.wallet.stub.exception.api;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class CredentialNotFoundExceptionTest {

    @Test
    void shouldCreateExceptionWithMessage() {
        // Given
        String expectedMessage = "Credential not found";

        // When
        CredentialNotFoundException exception = new CredentialNotFoundException(expectedMessage);

        // Then
        assertNotNull(exception);
        assertEquals(expectedMessage, exception.getMessage());
    }

    @Test
    void shouldCreateExceptionWithNullMessage() {
        // When
        CredentialNotFoundException exception = new CredentialNotFoundException(null);

        // Then
        assertNotNull(exception);
        assertNull(exception.getMessage());
    }
} 