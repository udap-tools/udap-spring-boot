package org.udap.config;

import java.net.URI;
import java.util.List;

import com.nimbusds.jose.jwk.JWKSet;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * UDAP - FHIR CLient Properties
 *
 * TODO: Add validation
 *
 * @author Brett P Stringham
 *
 */
@NoArgsConstructor
@Data
public class UdapFhirClient {

    private String clientNickname;

    /**
     * Software statement default values
     */
    private String clientName;

    private List<URI> redirectUris;

    private List<URI> contacts;

    private URI logoUri;

    private List<String> grantTypes;

    private List<String> responseTypes;

    private String tokenEndpointAuthMethod;

    private List<String> scopes;

    /**
     * X509 Certificate - FHIR Client Identity NOTE: In a production system this should be
     * persisted on some type of configuration service. For this example implementation,
     * it will reside on a file system
     */
    private String x509Location;

    /**
     * Private Key location corresponding to the FHIR Client's x509 Certificate NOTE: In a
     * production system the private key would be persisted in in a protected service such
     * as credential vault. For this example implementation it will reside on a file
     * system
     */
    private String privateKeyLocation;

    /**
     * Private key secret TODO: Support secret vaulting
     */
    private String privateKeySecret;
    
    /**
     * JWK Set created from private key located as the privateKeyLocation
     */
    private JWKSet privateJwkSet;

    /**
     * STU1 - SHALL be no more than 5 minutes (expressed in seconds)
     */
    private Integer softwareStatementTtl;

    /**
     * STU1 - SHALL be no more than 5 minutes (expressed in seconds) See
     * http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
     */
    private Integer authNTokenTtl;

    /**
     * Client ID when circumstances where this client has already registered with an
     * authorization server
     */
    private String clientId;

    /**
     * ONLY FOR INTEGRATION TESTS - so various FHIR Clients can be exercised Expected X509
     * Principle Name
     */
    private String integrationTestX509PrincpleNameExpected;

    /**
     * ONLY FOR INTEGRATION TESTS - so various FHIR Clients can be exercised Expected x509
     * Subject Alternative Name
     */
    private String integrationTestX509SanExpected;

}
