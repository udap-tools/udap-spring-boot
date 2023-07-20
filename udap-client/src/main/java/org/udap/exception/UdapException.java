package org.udap.exception;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Place holder - to be refined as robust error and exception handling is put in place.
 *
 * @author Brett P Stringham
 *
 */
@AllArgsConstructor
@Data
@EqualsAndHashCode(callSuper=false)
public class UdapException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String error;

    @JsonProperty("error_message")
    private final String errorMessage;

    /*
    public UdapException(WebClientResponseException e) {

    }
    */
}
