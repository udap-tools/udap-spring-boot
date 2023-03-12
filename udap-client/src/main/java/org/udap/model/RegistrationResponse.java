package org.udap.model;

import java.net.URI;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Reference: https://www.udap.org/udap-dynamic-client-registration-stu1.html#section-5.1
 *
 * Registration response as per Section 3.2.1 of RFC 7591.
 *
 * @author Brett P Stringham
 *
 */
@NoArgsConstructor
@Data
public class RegistrationResponse {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("software_statement")
    private String softwareStatement;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("redirect_uris")
    private List<URI> redirectUris;

    @JsonProperty("grant_types")
    private List<String> grantTypes;

    @JsonProperty("response_types")
    private List<String> responseTypes;

    @JsonProperty("token_endpoint_auth_method")
    private String tokenEndpointAuthMethod;

}
