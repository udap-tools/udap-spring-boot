package org.udap.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Builder;
import lombok.Data;

/**
 * @author Brett P Stringham
 *
 */
@Data
@Builder
public class AuthZExtensionHl7B2bHeader extends AuthZExtension {
    @JsonInclude(Include.NON_NULL)
    @JsonProperty("hl7-b2b")
    private AuthZExtensionHl7B2b hl7B2b;
}
