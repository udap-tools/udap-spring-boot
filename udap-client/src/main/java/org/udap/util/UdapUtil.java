package org.udap.util;

import java.io.IOException;
import java.net.URI;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.BodyInserters.FormInserter;
import org.springframework.web.reactive.function.client.WebClient;
import org.udap.config.UdapFhirClient;
import org.udap.model.AccessTokenResponse;
import org.udap.model.AuthZExtension;
import org.udap.model.RegistrationRequest;
import org.udap.model.RegistrationResponse;
import org.udap.model.ServerMetadata;
import org.udap.model.TokenRequestClientCredentialsGrant;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.mint.ConfigurableJWSMinter;
import com.nimbusds.jose.mint.DefaultJWSMinter;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import io.netty.handler.logging.LogLevel;
import lombok.extern.slf4j.Slf4j;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.logging.AdvancedByteBufFormat;

/**
 * Generic utility that support base UDAP specifications
 *
 * @author Brett P. Stringham
 *
 */
@Slf4j
public final class UdapUtil {

    private UdapUtil() {

    }

    /**
     * http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements
     */
    private static final Set<String> SERVER_METADATA_CLAIMS = new HashSet<>(Arrays.asList("sub", "exp", "iat", "jti",
            "authorization_endpoint", "token_endpoint", "registration_endpoint"));

    /**
     * TODO: Refine / replace with a performant method
     * @param date
     * @param ttl
     * @return
     */
    public static Date addSecondsToDate(Date date, int ttl /* seconds */) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.SECOND, ttl);

        return calendar.getTime();
    }

    /**
     * @param x509Certificate
     * @return
     * @throws CertificateParsingException
     */
    public static String getSubjectAlternativeName(X509Certificate x509Certificate) throws CertificateParsingException {
    	// TODO: Need to harden / refine
        Optional<List<?>> sanExtension = x509Certificate.getSubjectAlternativeNames().stream().findFirst();

        if (sanExtension.isPresent()) {
            List<?> sanEntry = sanExtension.get();
            return sanEntry.get(1 /* 2nd element */).toString();
        }

        return null;
    }
    
    /**
     * Create client's software statement to-be incorporated into the clients trusted
     * dynamic client registration request
     * @param fhirClient - FHIR client values such as name and certificate location
     * @param audience - The Authorization Server's "registration URL" (the same URL to
     * which the registration request will be posted)
     * @return
     * @throws IOException
     * @throws CertificateParsingException
     */
    public static JWTClaimsSet createSoftwareStatement(final UdapFhirClient fhirClient, final String audience)
            throws IOException, CertificateParsingException {
        final X509Certificate clientX509 = CommonUtil.readX509File(URI.create(fhirClient.getX509Location()));

        // iss required Issuer of the JWT -- unique identifying client URI. This SHALL
        // match the value of a uniformResourceIdentifier entry in the Subject Alternative
        // Name extension of the client's certificate included in the x5c JWT header
        final String iss = getSubjectAlternativeName(clientX509);

        // sub required Same as iss. In typical use, the client application will not yet
        // have a client_id from the Authorization Server
        final String sub = iss;

        // iat required Issued time integer for this software statement, expressed in
        // seconds since the "Epoch"
        final Date issueTime = new Date();

        // exp required Expiration time integer for this software statement, expressed in
        // seconds since the "Epoch" (1970-01-01T00:00:00Z UTC). The exp time SHALL be no
        // more than 5 minutes after the value of the iat claim.
        final Date expirationTime = addSecondsToDate(issueTime, fhirClient.getSoftwareStatementTtl());

        // jti required A nonce string value that uniquely identifies this software
        // statement. This value SHALL NOT be reused by the client app in another software
        // statement or authentication JWT before the time specified in the exp claim has
        // passed
        final String jti = UUID.randomUUID().toString();

        final JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder().issuer(iss)
            .subject(sub)
            // The Authorization Server's "registration URL" (the same URL to which the
            // registration request will be posted)
            .audience(audience)
            .issueTime(issueTime)
            .expirationTime(expirationTime)
            .jwtID(jti)
            // client_name required A string containing the human readable name of the
            // client application
            .claim("client_name", fhirClient.getClientName())
            // contacts required An array of URI strings indicating how the data holder
            // can contact the app operator regarding the application. The array SHALL
            // contain at least one valid email address using the mailto scheme, e.g.
            // ["mailto:operations@example.com"]
            .claim("contacts", fhirClient.getContacts())
            // logo_uri conditional A URL string referencing an image associated with the
            // client application, i.e. a logo. If grant_types includes
            // "authorization_code", client applications SHALL include this field, and the
            // Authorization Server MAY display this logo to the user during the
            // authorization process. The URL SHALL use the https scheme and reference a
            // PNG, JPG, or GIF image file, e.g. "https://myapp.example.com/MyApp.png"
            .claim("logo_uri", fhirClient.getLogoUri())
            // grant_types required Array of strings, each representing a requested grant
            // type, from the following list: "authorization_code", "refresh_token",
            // "client_credentials". The array SHALL include either "authorization_code"
            // or "client_credentials", but not both. The value "refresh_token" SHALL NOT
            // be present in the array unless "authorization_code" is also present.
            .claim("grant_types", fhirClient.getGrantTypes())
            // // scope required String containing a space delimited list of scopes
            // requested by the client application for use in subsequent requests. The
            // Authorization Server MAY consider this list when deciding the scopes that
            // it will allow the application to subsequently request. Note for client apps
            // that also support the SMART App Launch framework: apps requesting the
            // "client_credentials" grant type SHOULD request system scopes; apps
            // requesting the "authorization_code" grant type SHOULD request user or
            // patient scopes.
            .claim("scopes", fhirClient.getScopes())
            // token_endpoint_auth_method required Fixed string value: "private_key_jwt"
            .claim("token_endpoint_auth_method", fhirClient.getTokenEndpointAuthMethod());

        // response_types conditional Array of strings. If grant_types contains
        // "authorization_code", then this element SHALL have a fixed value of ["code"],
        // and SHALL be omitted otherwise
        if (fhirClient.getResponseTypes() != null && !fhirClient.getResponseTypes().isEmpty()) {
            claimsSetBuilder.claim("response_types", fhirClient.getResponseTypes());
        }

        // redirect_uris conditional An array of one or more redirection URIs used by the
        // client application. This claim SHALL be present if grant_types includes
        // "authorization_code" and this claim SHALL be absent otherwise. Each URI SHALL
        // use the https scheme.
        if (fhirClient.getRedirectUris() != null && !fhirClient.getRedirectUris().isEmpty()) {
            claimsSetBuilder.claim("redirect_uris", fhirClient.getRedirectUris());
        }

        return claimsSetBuilder.build();
    }

    /**
     * 3.1 <a href=
     * "http://hl7.org/fhir/us/udap-security/registration.html#software-statement">Software
     * Statement</a>
     * @param claimsSet
     * @param rsaJwk
     * @param rsaAlg
     * @return
     * @throws JOSEException
     */
    public static JWSObject createJwtWithSignature(final JWTClaimsSet claimsSet, final JWKSet jwkSet,
            final JWSAlgorithm rsaAlg) throws JOSEException {
        final JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);

        final ConfigurableJWSMinter<SecurityContext> minter = new DefaultJWSMinter<>();
        minter.setJWKSource(jwkSource);

        final JWSHeader header = new JWSHeader.Builder(rsaAlg).type(JOSEObjectType.JWT).build();

        return minter.mint(header, claimsSet.toPayload(), null);
    }

    /**
     * Helper function to construct a JWT Authentication Token See -
     * http://hl7.org/fhir/us/udap-security/b2b.html#constructing-authentication-token
     * @param fhirClient - FHIR client values such as name and certificate location
     * @param audience - The FHIR Authorization Server's token endpoint URL
     * @return
     * @throws IOException
     * @throws CertificateParsingException
     */
    public static Builder createAuthNToken(final UdapFhirClient fhirClient, final String audience) {
        /**
         * NOTE FROM UDAP.org: UDAP Test Tool 1.0.18: Tests 7, 18 and 20 have now been
         * updated accordingly; the 'sub' value of Authentication JWTs must now be set to
         * the client_id.
         */
        // iss required The application's client_id as assigned by the Authorization
        // Server during the registration process
        final String iss = fhirClient.getClientId();

        // sub required The application's client_id as assigned by the Authorization
        // Server during the registration process
        final String sub = fhirClient.getClientId();

        // iat required Issued time integer for this authentication JWT, expressed in
        // seconds since the "Epoch"
        final Date issueTime = new Date();

        // exp required Expiration time integer for this authentication JWT, expressed in
        // seconds since the "Epoch" (1970-01-01T00:00:00Z UTC)
        final Date expirationTime = addSecondsToDate(issueTime, fhirClient.getAuthNTokenTtl());

        // jti required A string value that uniquely identifies this authentication JWT.
        // This value SHALL NOT be reused by the client
        // app in another authentication JWT before the time specified in the exp claim
        // has passed
        final String jti = UUID.randomUUID().toString();

        return new JWTClaimsSet.Builder().issuer(iss)
            .subject(sub)
            // The FHIR Authorization Server's token endpoint URL
            .audience(audience)
            .issueTime(issueTime)
            .expirationTime(expirationTime)
            .jwtID(jti);
    }

    /**
     * Attaches Extension Object (prior to digital signature) to an JWT - Authorization
     * Token (i.e., claimset)
     * @param <E>
     * @param claimsSet - Existing claim set produced by createAuthNToken
     * @param extension - An authorization extension object to be included claims set
     * before formal digital signing
     * @return
     * @throws JsonProcessingException
     * @throws ParseException
     */
    public static <E extends AuthZExtension> Builder appendAuthNExtension(final Builder claimsSetBuilder,
            final E extension) throws JsonProcessingException, ParseException {
        Map<String, Object> claims = claimsSetBuilder.getClaims();

        try {
            log.debug("AuthZExtension ", extension);

            if (!claims.containsKey("extensions")) {
                String ext = CommonUtil.getObjectAsJson(extension);

                claimsSetBuilder.claim("extensions",
                        JSONObjectUtils.parse(ext) /* emptyExtensionList */);
            } else {
            	// TODO: Add to existing list of AuthN extensions
            }
        } catch (ClassCastException e) {
            log.error("ClassCastException: {}", e);

            throw e;
        }

        return claimsSetBuilder;
    }

    /**
     * Helper to create form data that will be used in the HTTP post to the token endpoint
     * @param tokenRequest
     * @return
     */
    public static FormInserter<String> getFormInserter(TokenRequestClientCredentialsGrant tokenRequest) {
        return BodyInserters.fromFormData("grant_type", tokenRequest.getGrantType())
            .with("client_assertion_type", tokenRequest.getClientAssertionType().toString())
            .with("client_assertion", tokenRequest.getClientAssertion())
            .with("scope", tokenRequest.getScope())
            .with("udap", tokenRequest.getUdap());
    }

    /**
     * Helper to check endpoints returned by ServerMetadata match the corresponding ]
     * "_endpoint" claims from the JWT Claim Set (whose signature was validated prior)
     * from a valid Signed Server Metadata
     * @param serverMetadata
     * @param metadataClaimsSet
     * @return
     * @throws ParseException
     */
    public static boolean isServerMetadataTrusted(final ServerMetadata serverMetadata,
            final JWTClaimsSet metadataClaimsSet) throws ParseException {
        Assert.notNull(serverMetadata, "serverMetadata cannot be null");
        Assert.notNull(metadataClaimsSet, "metadataClaimsSet cannot be null");

        // final String authorizationEndpoint = metadataClaimsSet.getStringClaim("authorization_endpoint");
        final String registrationEndpoint = metadataClaimsSet.getStringClaim("registration_endpoint");
        final String tokenEndpoint = metadataClaimsSet.getStringClaim("token_endpoint");
        if (/* authorizationEndpoint == null || */registrationEndpoint == null || tokenEndpoint == null) {
            log.warn("Server metadata mismatch; not trusted");
            return false;
        }

        return registrationEndpoint.compareTo(serverMetadata.getRegistrationEndpoint()) == 0
                || tokenEndpoint.compareTo(serverMetadata.getTokenEndpoint()) == 0;
                // authorizationEndpoint.compareTo(serverMetadata.getAuthorizationEndpoint()) == 0 ||
    }

    /**
     * Helper to validate server's metadata signature and then extracts claims for a
     * validation check before considering the server fully trusted
     * @param serverMetadata
     * @param expectedIssuer
     * @return
     * @throws ParseException
     * @throws JOSEException
     * @throws BadJOSEException
     */
    public static boolean isServerMetadataTrusted(final ServerMetadata serverMetadata, final String expectedIssuer,
            final JWSAlgorithm jwsAlg) throws ParseException, JOSEException, BadJOSEException {
        Assert.notNull(serverMetadata, "serverMetadata cannot be null");

        JWTClaimsSet serverMetadataClaimsSet = getClaimsFromSignedServerMetadata(serverMetadata.getSignedMetadata(),
                expectedIssuer, jwsAlg);
        
        return isServerMetadataTrusted(serverMetadata, serverMetadataClaimsSet);
    }

    /**
     * 2.3 Signed metadata elements
     * @See http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements
     * @param signedMetadata
     * @param publicKeyToValidateSignature
     * @param requiredIssuer
     * @param expectedJWSAlg
     * @return
     * @throws JOSEException
     * @throws BadJOSEException
     * @throws ParseException
     */
    public static JWTClaimsSet getClaimsFromSignedServerMetadata(final String signedMetadata,
            final String requiredIssuer, final JWSAlgorithm expectedJWSAlg)
            throws ParseException, JOSEException, BadJOSEException {
        Assert.hasText(signedMetadata, "metadataJwt cannot be empty");
        Assert.hasText(requiredIssuer, "requiredIssuer cannot be empty");
        Assert.notNull(expectedJWSAlg, "expectedJWSAlg cannot be null");

        final JWSObject jwsObject = JWSObject.parse(signedMetadata);
        final List<Base64> x5c = jwsObject.getHeader().getX509CertChain();
        final X509Certificate serverCertificate;
        if (x5c != null && !x5c.isEmpty()) {
            serverCertificate = X509CertUtils.parse(x5c.get(0).decode());
        } else {
            // TODO: throw UDAP Exception object
            return null;
        }

        final JWKSet jwkSet = new JWKSet(JWK.parse(serverCertificate));

        final JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(jwkSet);
        final JWSKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(expectedJWSAlg,
                jwkSource);

        final DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);

        /**
         * 2.3 Signed metadata elements
         * @See http://hl7.org/fhir/us/udap-security/discovery.html#signed-metadata-elements
         * iss required sub required exp required iat required jti required
         * authorization_endpoint conditional token_endpoint required
         * registration_endpoint required
         *
         * DefaultJWTClaimsVerifier:
         * https://www.javadoc.io/doc/com.nimbusds/nimbus-jose-jwt/latest/com/nimbusds/jwt/proc/DefaultJWTClaimsVerifier.html
         */
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer(requiredIssuer).build(), SERVER_METADATA_CLAIMS));

        return jwtProcessor.process(signedMetadata, null /* Optional SecurityContext */);
    }

    /**
     * Helper to retrieve UDAP server metadata at the /.well-known/udap endpoint
     * @param baseUrl
     * @return
     */
    public static ServerMetadata getServerMetadata(String baseUrl) {
        WebClient webClient = WebClient.builder()
            .baseUrl(baseUrl)
            .defaultHeader("Accept", MediaType.APPLICATION_JSON_VALUE)
            .build();

        final ResponseEntity<ServerMetadata> metadataResponse = webClient.get()
            .uri("/.well-known/udap")
            .retrieve()
            .toEntity(ServerMetadata.class)
            .block(Duration.ofMinutes(2));

        if (metadataResponse != null && metadataResponse.getStatusCode() == HttpStatus.OK) {
            return metadataResponse.getBody();

        } /**else {
            // TODO: Handle error scenarios
        }*/

        return null;

    }

    /**
     * Performs registration of UDAP client at the appropriate URL as identified in the
     * ServerMetadata that has been digitally signed with the FHIR client's private key
     * @param fhirClient
     * @param serverMetadata
     * @return
     * @throws CertificateException
     * @throws IOException
     * @throws JOSEException
     */
    public static RegistrationResponse registerClient(final UdapFhirClient fhirClient,
            final ServerMetadata serverMetadata, final String udapVersion, final JWKSet privateJwkSet)
            throws CertificateException, IOException, JOSEException {

        String registrationEndpoint = serverMetadata.getRegistrationEndpoint();

        // Create client software statement then sign with the client's private key
        JWTClaimsSet claimsSet = createSoftwareStatement(fhirClient, registrationEndpoint);
        JWSObject signedStatement = createJwtWithSignature(claimsSet, privateJwkSet, JWSAlgorithm.RS256);

        //////////////////////////////////////////////////////////////////
        // https://www.udap.org/UDAPTestTool/
        // Client APP TEST - Test 3: Trusted dynamic client registration
        //////////////////////////////////////////////////////////////////
        RegistrationRequest registrationRequest = RegistrationRequest.builder()
            .softwareStatement(signedStatement.serialize())
            .udap(udapVersion)
            .build();

        // TODO: Support automatic debug logging only when necessary
        HttpClient httpClient = HttpClient.create()
            .wiretap("reactor.netty.http.client.HttpClient", LogLevel.DEBUG, AdvancedByteBufFormat.TEXTUAL);

        WebClient webClient = WebClient.builder().clientConnector(new ReactorClientHttpConnector(httpClient)).build();

        ResponseEntity<RegistrationResponse> response = webClient.post()
            .uri(registrationEndpoint)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(registrationRequest))
            .retrieve()
            .toEntity(RegistrationResponse.class)
            .block(Duration.ofMinutes(2));

        if (response != null && response.getStatusCode().is2xxSuccessful()) {
            return response.getBody();
        }

        return null;
    }

    /**
     * Post authN token to token endpoint to receive access token
     * @param authNToken
     * @param tokenEndpoint
     * @return
     */
    public static AccessTokenResponse getAccessToken(final JWSObject authNToken, final String tokenEndpoint, final String scope) {
        TokenRequestClientCredentialsGrant authNTokenRequest = TokenRequestClientCredentialsGrant.builder()
            .grantType("client_credentials")
            .clientAssertionType(URI.create("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"))
            .clientAssertion(authNToken.serialize())
            // TODO: pass as parameter
            .scope(scope)
            .udap("1")
            .build();

        log.debug("authNTokenRequest: {}", authNTokenRequest);

        // TODO: Support automatic debug logging only when necessary
        HttpClient httpClient = HttpClient.create()
            .wiretap("reactor.netty.http.client.HttpClient", LogLevel.DEBUG, AdvancedByteBufFormat.TEXTUAL);

        WebClient webClient = WebClient.builder().clientConnector(new ReactorClientHttpConnector(httpClient)).build();

        // https://www.udap.org/udap-jwt-client-auth.html - SECTION 7
        ResponseEntity<AccessTokenResponse> response = webClient.post()
            .uri(tokenEndpoint)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .accept(MediaType.APPLICATION_JSON)
            .body(UdapUtil.getFormInserter(authNTokenRequest))
            .retrieve()
            // .onErrorMap(WebClientResponseException.class, e -> new
            // BadRequestResponse(e))
            .toEntity(AccessTokenResponse.class)
            .block(Duration.ofMinutes(2));

        // TODO: Implement robust error handling per WebClient best practices
        if (response != null && response.getStatusCode() == HttpStatus.OK) {
            return response.getBody();
        }

        return null;
    }

}
