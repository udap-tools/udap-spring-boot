package org.udap.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.Builder;
import lombok.Data;

/**
 * See http://hl7.org/fhir/us/udap-security/registration.html#request-body
 *
 * @author Brett P Stringham
 *
 */
@Builder
@Data
public class RegistrationRequest {

    /**
     * The software statement is signed and assembled using JWS compact serialization as
     * per RFC 7515.
     */
    @JsonProperty("software_statement")
    private String softwareStatement;

    /**
     * Authorization Servers MAY support the inclusion of certifications and endorsements
     * by client application operators using the certifications framework outlined in UDAP
     * Certifications and Endorsements for Client Applications. Authorization Servers
     * SHALL ignore unsupported or unrecognized certifications.
     *
     * See:
     * http://hl7.org/fhir/us/udap-security/registration.html#inclusion-of-certifications-and-endorsements
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("certifications")
    private List<String> certifications;

    /**
     * UDAP version - set to "1"
     */
    @JsonProperty("udap")
    private String udap;

}
