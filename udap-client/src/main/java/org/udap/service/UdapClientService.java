package org.udap.service;

import java.io.IOException;
import java.net.URI;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;

import org.springframework.stereotype.Service;
import org.udap.config.UdapFhirClient;
import org.udap.model.AccessTokenResponse;
import org.udap.model.AuthZExtension;
import org.udap.model.RegistrationResponse;
import org.udap.model.ServerMetadata;
import org.udap.util.CommonUtil;
import org.udap.util.UdapUtil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;

import lombok.extern.slf4j.Slf4j;

/**
 * UDAP Client Service to perform actions such as... Trusted Dynamic Client Registration
 * Getting an Access Token from a UDAP capable authorization server
 *
 * @author Brett P. Stringham
 *
 */
@Slf4j
@Service
public class UdapClientService {

    /**
     * Registers the default UDAP client at the given authorization server. Also performs
     * necessary checks on server metadata to ensure server is trusted
     * @param authorizationServer
     * @param expectedMetadataIssuer
     * @param udapVersion
     * @return RegistrationResponse
     */
    public RegistrationResponse register(final UdapFhirClient fhirClient, 
    		final String authorizationServer, final String expectedMetadataIssuer,
            final String udapVersion, final boolean mustBeTrusted) {
    	
        // TODO: Create service that caches information on trusted servers with
        // configurable "re-validate" intervals
        final ServerMetadata serverMetadata = UdapUtil.getServerMetadata(authorizationServer);
        boolean isServerTrusted;
        try {
            // UDAP Client - Private Key
            final URI privateKeyLocation = URI.create(fhirClient.getPrivateKeyLocation());
            final JWKSet privateJwkSet = CommonUtil.getJwkSetFromPkcs12(privateKeyLocation,
            		fhirClient.getPrivateKeySecret().toCharArray());
                
            if (mustBeTrusted) {
                isServerTrusted = UdapUtil.isServerMetadataTrusted(serverMetadata, expectedMetadataIssuer,
                        JWSAlgorithm.RS256);
            } else {
                isServerTrusted = true;
                log.warn("Authorization server - trust assumed! mustBeTrusted set to {}", mustBeTrusted);
            }

            if (isServerTrusted) {
                return UdapUtil.registerClient(fhirClient, serverMetadata, udapVersion, privateJwkSet);
            } else {
                log.error(authorizationServer + " is not trusted");
            }
        } catch (ParseException | CertificateException | IOException | BadJOSEException | JOSEException | KeyStoreException | NoSuchAlgorithmException e) {
            log.error("UDAP Registration Error: {}", e.getMessage());
        }

        return null;
    }

    /**
     * UDAP JWT Based Authentication with support for Authorization Extensions
     * @param authorizationServer
     * @param expectedMetadataIssuer
     * @param authNExtensionList
     * @return
     */
    public AccessTokenResponse getAccessToken(final UdapFhirClient fhirClient, 
    		final String authorizationServer, final String expectedMetadataIssuer, final String scope,
            final List<AuthZExtension> authNExtensionList, final boolean mustBeTrusted) {
    	
        // TODO: Create service that caches information on trusted servers with
        // configurable "re-validate" intervals
        final ServerMetadata serverMetadata = UdapUtil.getServerMetadata(authorizationServer);
        final boolean isServerTrusted;
        try {
            // UDAP Client - Private Key
            final URI privateKeyLocation = URI.create(fhirClient.getPrivateKeyLocation());
            final JWKSet privateJwkSet = CommonUtil.getJwkSetFromPkcs12(privateKeyLocation,
            		fhirClient.getPrivateKeySecret().toCharArray());
            
            if (mustBeTrusted) {
                isServerTrusted = UdapUtil.isServerMetadataTrusted(serverMetadata, expectedMetadataIssuer,
                        JWSAlgorithm.RS256);
            } else {
                isServerTrusted = true;
                log.warn("Authorization server - trust assumed! mustBeTrusted set to {}", mustBeTrusted);
            }

            if (isServerTrusted) {
                String tokenEndPoint = serverMetadata.getTokenEndpoint();

                // http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
                Builder authNTokenBuilder = UdapUtil.createAuthNToken(fhirClient, tokenEndPoint);

                // Attach available authorization extensions to access token request
                for (AuthZExtension extension : authNExtensionList) {
                    log.debug("Appending AuthZ Extension: {}", CommonUtil.getObjectAsJson(extension));
                    UdapUtil.appendAuthNExtension(authNTokenBuilder, extension);
                }

                JWTClaimsSet authNClaims = authNTokenBuilder.build();

                // http://hl7.org/fhir/us/udap-security/b2b.html#client-credentials-grants
                JWSObject authNToken = UdapUtil.createJwtWithSignature(authNClaims, privateJwkSet,
                        JWSAlgorithm.RS256);

                log.info("AuthN Token: " + authNToken.serialize());

                return UdapUtil.getAccessToken(authNToken, tokenEndPoint, scope);

            } else {
                log.error(authorizationServer + " is not trusted");
            }
        } catch (ParseException | IOException | BadJOSEException | JOSEException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            log.error("UDAP error getting access token: {}", e.getMessage());
        }

        return null;
    }

}
