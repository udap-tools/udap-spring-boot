package org.udap.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Pool of UDAP FHIR Clients that are configured based upon their associated trust
 * community.
 *
 * @author Brett P Stringham
 *
 */
@Configuration
@ConfigurationProperties
@NoArgsConstructor
@Data
public class UdapFhirClientPool {

    /**
     * Nickname for default FHIR client
     */
    private String fhirClientDefault;

    /**
     * UDAP FHIR Clients - support more that one client in this reference
     */
    private List<UdapFhirClient> fhirClients;

}