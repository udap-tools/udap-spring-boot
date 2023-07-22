package org.udap.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.udap.config.UdapFhirClient;
import org.udap.config.UdapFhirClientPool;
import org.udap.model.*;
import org.udap.service.UdapClientService;
import org.udap.util.CommonUtil;

import java.io.IOException;
import java.net.URI;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
@SpringBootTest
@ActiveProfiles("test")
@Import({UdapFhirClientPool.class})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UdapClientTests {
    @Autowired
    private UdapFhirClientPool udapFhirClientPool;

    private UdapClientService udapClientService;

    @PostConstruct
    void onPostConstruct() {
        udapClientService = new UdapClientService();

        Assert.notNull(udapFhirClientPool, "Missing fhirClientPool");
        Assert.notNull(udapFhirClientPool.getFhirClients(), "Missing fhirClientPool list");
        Assert.notEmpty(udapFhirClientPool.getFhirClients(), "fhirClientPool empty");
    }

    @Test
    @DisplayName("Verify UDAP Client - X509 SAN and Principal")
    @Order(1)
    void checkX509Properties() throws IOException, CertificateParsingException {
        assertThat(udapClientService).isNotNull();

        final UdapFhirClient fhirClient = udapFhirClientPool.getFhirClients().get(0);

        URI x509Location = URI.create(fhirClient.getX509Location());
        X509Certificate x509 = CommonUtil.readX509File(x509Location);

        assertEquals(1, x509.getSubjectAlternativeNames().size());

        List<?> sanExtension = x509.getSubjectAlternativeNames().stream().findFirst().get();

        assertEquals(fhirClient.getIntegrationTestX509PrincpleNameExpected(), x509.getSubjectX500Principal().getName());
        assertEquals(fhirClient.getIntegrationTestX509SanExpected(), sanExtension.get(1));
    }

    @Test
    @DisplayName("Hatch UDAP Client - private key from file")
    @Order(2)
    void hatchPrivateKeyFile() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException {
        assertThat(udapClientService).isNotNull();

        final UdapFhirClient fhirClient = udapFhirClientPool.getFhirClients().get(0);

        URI privateKeyLocation = URI.create(fhirClient.getPrivateKeyLocation());
        PrivateKey privateKey = CommonUtil.getPrivateKey(privateKeyLocation, fhirClient.getPrivateKeySecret().toCharArray());

        assertEquals(0, "RSA".compareTo(privateKey.getAlgorithm()));
    }

    @Test
    @DisplayName("UDAP client - register with AS")
    @Order(3)
    void registerUdapClient() {
        // TODO: Use mock servers for integration test
        final String defaultAuthorizationServer = "https://example.com/";
        final String expectedMetadataIssuer = "https://example.com/";

        final UdapFhirClient fhirClient = udapFhirClientPool.getFhirClients().get(0);

        // Perform (UDAP) Trusted Dynamic Client Registration
        assertThrows(WebClientResponseException.class, () -> {
            RegistrationResponse response = udapClientService.register(fhirClient,
                    defaultAuthorizationServer, expectedMetadataIssuer,
                    "1" /* UDAP Version */, true /* must be trusted */);

            // 	Client ID necessary in Test #4
            fhirClient.setClientId(response.getClientId());

            log.info("response: {}", response);
        });
    }

    @Test
    @DisplayName("UDAP Client - request access token from AS")
    @Order(4)
    void getAccessTokenWithDefaultUdapClient() throws JsonProcessingException {
        //TODO: Use mock servers for integration test

        final String defaultAuthorizationServer = "https://example.com/";
        final String expectedMetadataIssuer = "https://example.com/";
        final String scope = "system/Procedures.read";

        ////////////////////////////////////////////////////////////////////////
        // https://www.udap.org/UDAPTestTool/
        // Client APP TEST - Test 9: JWT-Based Client Authentication (client credentials
        //////////////////////////////////////////////////////////////////////// flow)
        ////////////////////////////////////////////////////////////////////////

        // http://hl7.org/fhir/us/udap-security/b2b.html#b2b-authorization-extension-object
        AuthZExtensionHl7B2b hl7B2bExtension = AuthZExtensionHl7B2b.builder()
                .version("1")
                .organizationId("https://example.com/Organization/2.16.840.1.113883.301.560.6999")// Per
                // TEFCA
                // IG
                // --
                // TBA)
                .organizationName("ABC Hospital")
                .subjectId("Dr. ABC Physician")
                // pg 24. Table 7 -
                // https://rce.sequoiaproject.org/wp-content/uploads/2022/01/QTF_0122.pdf
                .purposeOfUse(Arrays.asList("TREATMENT"))
                .build();

        AuthZExtensionHl7B2bHeader hl7B2bHeader = AuthZExtensionHl7B2bHeader.builder().hl7B2b(hl7B2bExtension).build();

        final List<AuthZExtension> authZExtensionList = Arrays.asList(hl7B2bHeader);

        final UdapFhirClient fhirClient = udapFhirClientPool.getFhirClients().get(0);

        // Perform (UDAP) Trusted Dynamic Client Registration
        assertThrows(WebClientResponseException.class, () -> {
                    AccessTokenResponse response = udapClientService.getAccessToken(fhirClient,
                            defaultAuthorizationServer, expectedMetadataIssuer, scope,
                            authZExtensionList, true);

                    log.info("response: {}", response);
                }
        );
    }
}
