package org.udap.exception;

import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Place holder - to be refined as robust error and exception handling is put in place.
 *
 * @author Brett P Stringham
 *
 */
@AllArgsConstructor
@Data
public class UdapException extends Throwable {

    private static final long serialVersionUID = 1L;

    private String error;

    @JsonProperty("error_message")
    private String errorMessage;

    public UdapException(WebClientResponseException e) {

    }

}
