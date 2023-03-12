package org.udap.model;

import java.net.URI;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.Builder;
import lombok.Data;

/**
 *
 * Token request - Authorization code grant See
 * http://hl7.org/fhir/us/udap-security/b2b.html#authorization-code-grant
 *
 * @author Brett P Stringham
 *
 */
@Builder
@Data
public class TokenRequestAuthZCodeGrant {

    /**
     * grant_type required Fixed value: authorization_code
     */
    @JsonProperty("grant_type")
    private String grantType;

    /**
     * code required The code that the app received from the Authorization Server
     */
    @JsonProperty("code")
    private String code;

    /**
     * redirect_uri conditional The client application's redirection URI. This parameter
     * SHALL be present only if the redirect_uri parameter was included in the
     * authorization request in Section 5.1, and their values SHALL be identical.
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("redirect_uri")
    private URI redirectUri;

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
    private URI clientAssertion;

    /**
     * udap required Fixed value: 1
     */
    @JsonProperty("udap")
    private URI udap;

}
