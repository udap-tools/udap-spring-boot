package org.udap.model;

import java.net.URI;
import java.net.URL;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import lombok.Builder;
import lombok.Data;

/**
 * B2B Authorization Extension Object See
 * http://hl7.org/fhir/us/udap-security/b2b.html#b2b-authorization-extension-object
 *
 * @author Brett P Stringham
 *
 */
@Builder
@Data
public class AuthZExtensionHl7B2b {

    /**
     * version required String with fixed value: "1"
     */
    @JsonProperty("version")
    private String version;

    /**
     * subject_name conditional String containing the human readable name of the human or
     * non-human requestor; required if known.
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("subject_name")
    private String subjectName;

    /**
     * subject_id conditional String containing a unique identifier for the requestor;
     * required if known for human requestors when the subject_name parameter is present.
     * For US Realm, the value SHALL be the subject's individual National Provider
     * Identifier (NPI); omit for non-human requestors and for requestors who have not
     * been assigned an NPI. See Section 5.2.1.2 below for the preferred format of the
     * identifier value string.
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("subject_id")
    private String subjectId;

    /**
     * subject_role conditional String containing a code identifying the role of the
     * requestor; required if known for human requestors when the subject_name parameter
     * is present. For US Realm, trust communities SHOULD constrain the allowed values and
     * formats, and are encouraged to draw from the National Uniform Claim Committee
     * (NUCC) Provider Taxonomy Code Set, but are not required to do so to be considered
     * conformant. See Section 5.2.1.2 below for the preferred format of the code value
     * string.
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("subject_role")
    private String subjectRole;

    /**
     * organization_name optional String containing the human readable name of the
     * organizational requestor. If a subject is named, the organizational requestor is
     * the organization represented by the subject.
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("organization_name")
    private String organizationName;

    /**
     * organization_id required String containing a unique identifier for the
     * organizational requestor. If a subject is named, the organizational requestor is
     * the organization represented by the subject. The identifier SHALL be a Uniform
     * Resource Identifier (URI). Trust communities SHALL define the allowed URI
     * scheme(s). If a URL is used, the issuer SHALL include a URL that is resolvable by
     * the receiving party.
     */
    @JsonProperty("organization_id")
    private String organizationId;

    /**
     * purpose_of_use required An array of one or more strings, each containing a code
     * identifying a purpose for which the data is being requested. For US Realm, trust
     * communities SHOULD constrain the allowed values, and are encouraged to draw from
     * the HL7 PurposeOfUse value set, but are not required to do so to be considered
     * conformant. See Section 5.2.1.2 below for the preferred format of each code value
     * string array element.
     */
    @JsonProperty("purpose_of_use")
    private List<String> purposeOfUse;

    /**
     * consent_policy optional An array of one or more strings, each containing a URI
     * identifiying a privacy consent directive policy or other policy consistent with the
     * value of the purpose_of_use parameter.
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("consent_policy")
    private List<URI> consentPolicy;

    /**
     * consent_reference conditional An array of one or more strings, each containing an
     * absolute URL consistent with a literal reference to a FHIR Consent or
     * DocumentReference resource containing or referencing a privacy consent directive
     * relevant to a purpose identified by the purpose_of_use parameter and the policy or
     * policies identified by the consent_policy parameter.
     */
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("consent_reference")
    private List<URL> consentReference;

}
