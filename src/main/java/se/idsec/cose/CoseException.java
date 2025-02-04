// SPDX-FileCopyrightText: 2016-2024 COSE-JAVA
// SPDX-FileCopyrightText: 2025 IDsec Solutions AB
//
// SPDX-License-Identifier: BSD-3-Clause

package se.idsec.cose;

/**
 *
 * @author jimsch
 */
public class CoseException extends Exception {
    public CoseException(String message) {
        super(message);
    }
    public CoseException(String message, Exception ex) {
        super(message, ex);
    }
}
