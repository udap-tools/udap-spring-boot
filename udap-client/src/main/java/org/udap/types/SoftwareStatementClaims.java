package org.udap.types;

/**
 * TODO: Cleanup and implement
 *
 * JWT claim names used to produce a FHIR client's signed software statement that will be
 * included as part of Trusted Dynamic Client Registration action performed at the FHIR
 * Server's AS /registration endpoint.
 *
 * http://hl7.org/fhir/us/udap-security/registration.html#software-statement
 *
 * @author Brett Stringham
 *
 */
public enum SoftwareStatementClaims {

    ISS("iss"), SUB("sub"), AUD("aud"), EXP("exp"), IAT("iat"), JTI("jti"), CLIENT_NAME("client_name"),
    REDIRECT_URIS("redirect_uris"), CONTACTS("contacts"), LOGO_URI("logo_uri"), GRANT_TYPES("grant_types"),
    RESPONSE_TYPES("response_types"), TOKEN_ENDPOINT_AUTH_METHOD("token_endpoint_auth_method"), SCOPE("scope");

    private final String name;

    SoftwareStatementClaims(String name) {
        this.name = name;
    }

}
