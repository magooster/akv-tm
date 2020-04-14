/*
 * Copyright 2020 Ian Cusden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package net.iaminnovative;

/** Thrown to indicate that a key vault operation has failed */
public class KeyVaultException extends RuntimeException {
    /** Constructs a KeyVaultException with no error message */
    public KeyVaultException() {
        super();
    }

    /**
     * Constructs a KeyVaultException with the specified error message.
     *
     * @param message the error message (Retrievable by the Throwable.getMessage() method)
     */
    public KeyVaultException(final String message) {
        super(message);
    }

    /**
     * Constructs a KeyVaultException with the specified error message and cause.
     *
     * @param message the error message (Retrievable by the Throwable.getMessage() method)
     * @param cause the cause (Retrievable by the Throwable.getCause() method)
     */
    public KeyVaultException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public KeyVaultException(final Throwable cause) {
        super(cause);
    }
}
