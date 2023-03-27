package org.udap.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

/**
 * The metadata returned from the UDAP metadata endpoint defined above SHALL represent the
 * server’s capabilities with respect to the UDAP workflows described in this
 * <a href="http://hl7.org/fhir/us/udap-security/discovery.html">guide</a>.
 *
 * @see <a href=
 * "http://hl7.org/fhir/us/udap-security/discovery.html#required-udap-metadata/">Required
 * UDAP Metadata</a>
 * @author Brett P Stringham
 *
 */
@NoArgsConstructor
@Data
public class ServerMetadata {

    @JsonProperty("udap_versions_supported")
    @NonNull
    private List<String> udapVersionsSupported;

    @JsonProperty("udap_profiles_supported")
    @NonNull
    private List<String> udapProfilesSupported;

    @JsonProperty("udap_authorization_extensions_supported")
    @NonNull
    private List<String> udapAuthorizationExtensionsSupported;

    @JsonProperty("udap_authorization_extensions_required")
    private List<String> udapAuthorizationExtensionsRequired;

    @JsonProperty("udap_certifications_supported")
    @NonNull
    private List<String> udapCertificationsSupported;

    @JsonProperty("udap_certifications_required")
    private List<String> udapCertificationsRequired;

    @JsonProperty("grant_types_supported")
    @NonNull
    private List<String> grantTypesSupported;

    @JsonProperty("scopes_supported")
    private List<String> scopesSupported;

    @JsonProperty("authorization_endpoint")
    private String authorizationEndpoint;

    @JsonProperty("token_endpoint")
    @NonNull
    private String tokenEndpoint;

    @JsonProperty("token_endpoint_auth_methods_supported")
    @NonNull
    private List<String> tokenEndpointAuthMethodsSupported;

    @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    @NonNull
    private List<String> tokenEndpointAuthSigningAlgValuesSupported;

    @JsonProperty("registration_endpoint")
    @NonNull
    private String registrationEndpoint;

    @JsonProperty("registration_endpoint_jwt_signing_alg_values_supported")
    private List<String> registrationEndpointJwtSigningAlgValuesSupported;

    @JsonProperty("signed_metadata")
    @NonNull
    private String signedMetadata;

}
