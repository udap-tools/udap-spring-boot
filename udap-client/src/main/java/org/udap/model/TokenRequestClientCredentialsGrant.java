package org.udap.model;

import java.net.URI;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.Builder;
import lombok.Data;

/**
 *
 * Access Token request - Client credentials grant See
 * http://hl7.org/fhir/us/udap-security/b2b.html#client-credentials-grant
 *
 * @author Brett P Stringham
 *
 */
@Builder
@Data
public class TokenRequestClientCredentialsGrant {

    /**
     * grant_type required Fixed value: authorization_code
     */
    @JsonProperty("grant_type")
    private String grantType;

    /**
     * client_assertion_type required Fixed value:
     * urn:ietf:params:oauth:client-assertion-type:jwt-bearer
     */
    @JsonProperty("client_assertion_type")
    private URI clientAssertionType;

    /**
     * client_assertion required The signed Authentication Token JWT
     */
    @JsonProperty("client_assertion")
    private String clientAssertion;

    /**
     * scope optional
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("scope")
    private String scope;

    /**
     * udap required Fixed value: 1
     */
    @JsonProperty("udap")
    private String udap;

}
