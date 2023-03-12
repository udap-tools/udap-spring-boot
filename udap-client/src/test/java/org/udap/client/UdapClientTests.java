package org.udap.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.udap.client.demo.tefca.PatientSearchService;
import org.udap.config.UdapFhirClientPool;
import org.udap.model.AccessTokenResponse;
import org.udap.model.AuthZExtension;
import org.udap.model.AuthZExtensionHl7B2b;
import org.udap.model.AuthZExtensionHl7B2bHeader;
import org.udap.model.RegistrationResponse;
import org.udap.service.UdapClientService;
import org.udap.util.CommonUtil;

import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SpringBootTest
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UdapClientTests {

    @Autowired
    private UdapClientService udapClientService;

    @Autowired
    private UdapFhirClientPool fhirClientPool;

    @Test
    void contextLoads() {
    }

    @Test
    @Order(1)
    void checkX509Properties() throws IOException, CertificateParsingException {
        assertThat(fhirClientPool).isNotNull();

        // For now -- test assume only 1 FHIR client is defined
        assertEquals(1, fhirClientPool.getFhirClients().size());

        var fhirClient = fhirClientPool.getFhirClients().get(0);
        var x509Location = URI.create(fhirClient.getX509Location());
        var x509 = CommonUtil.readX509File(x509Location);

        assertEquals(1, x509.getSubjectAlternativeNames().size());

        var sanExtension = x509.getSubjectAlternativeNames().stream().findFirst().get();

        assertEquals(fhirClient.getIntegrationTestX509PrincpleNameExpected(), x509.getSubjectX500Principal().getName());
        assertEquals(fhirClient.getIntegrationTestX509SanExpected(), sanExtension.get(1));
    }

    @Test
    @Order(2)
    void hatchPrivateKeyFile() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException {
        assertThat(fhirClientPool).isNotNull();

        // For now -- test assume only 1 FHIR client is defined
        assertEquals(1, fhirClientPool.getFhirClients().size());

        var fhirClient = fhirClientPool.getFhirClients().get(0);
        var privateKeyLocation = URI.create(fhirClient.getPrivateKeyLocation());
        var privateKey = CommonUtil.getPrivateKey(privateKeyLocation, fhirClient.getPrivateKeySecret().toCharArray());

        assertEquals(0, "RSA".compareTo(privateKey.getAlgorithm()));
    }

    // @Test
    // @Order(3)
    void registerUdapClient() {
        // "https://test.udap.org/fhir/r4/stage"
        // final String defaultAuthorizationServer =
        // "https://securefhir.zimt.work/udap-public";
        // final String expectedMetadataIssuer =
        // "https://securefhir.zimt.work/udap-public";

        // final String defaultAuthorizationServer =
        // "https://stage.healthtogo.me:8181/fhir/r4/stage";
        // final String expectedMetadataIssuer =
        // "https://stage.healthtogo.me:8181/fhir/r4/stage";

        // final String defaultAuthorizationServer = "https://fhirlabs.net/fhir/r4";
        // final String expectedMetadataIssuer = "https://fhirlabs.net/fhir/r4";

        // final String defaultAuthorizationServer = "https://udap.fast.poolnook.me";
        // final String expectedMetadataIssuer =
        // "https://test.healthtogo.me/udap-sandbox/evernorth";

        final String defaultAuthorizationServer = "https://mktac-restapis-stable.meditech.com/";
        final String expectedMetadataIssuer = "https://mktac-restapis-stable.meditech.com/";

        // Perform (UDAP) Trusted Dynamic Client Registration
        RegistrationResponse response = udapClientService.register(defaultAuthorizationServer, expectedMetadataIssuer,
                "1" /* UDAP Version */, false /* must be trusted */);
        log.info("Registration response: {}", response);

        assertTrue(true);
    }

    @Test
    @Order(3)
    void getAccessTokenWithDefaultUdapClient() throws JsonProcessingException {
        // "https://test.udap.org/fhir/r4/stage"
        // final String defaultAuthorizationServer =
        // "https://securefhir.zimt.work/udap-public";
        // final String expectedMetadataIssuer =
        // "https://securefhir.zimt.work/udap-public";

        // final String defaultAuthorizationServer =
        // "https://stage.healthtogo.me:8181/fhir/r4/stage";
        // final String expectedMetadataIssuer =
        // "https://stage.healthtogo.me:8181/fhir/r4/stage";

        // final String defaultAuthorizationServer = "https://fhirlabs.net/fhir/r4";
        // final String expectedMetadataIssuer = "https://fhirlabs.net/fhir/r4";

        // final String defaultAuthorizationServer = "https://udap.fast.poolnook.me";
        // final String expectedMetadataIssuer =
        // "https://test.healthtogo.me/udap-sandbox/evernorth";

        final String defaultAuthorizationServer = "https://mktac-restapis-stable.meditech.com/";
        final String expectedMetadataIssuer = "https://mktac-restapis-stable.meditech.com/";

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
            .subjectId("Dr. Future Stringham")
            // pg 24. Table 7 -
            // https://rce.sequoiaproject.org/wp-content/uploads/2022/01/QTF_0122.pdf
            .purposeOfUse(Arrays.asList("TREATMENT"))
            .build();

        AuthZExtensionHl7B2bHeader hl7B2bHeader = AuthZExtensionHl7B2bHeader.builder().hl7B2b(hl7B2bExtension).build();

        final List<AuthZExtension> authZExtensionList = Arrays.asList(hl7B2bHeader);

        // Perform (UDAP) Trusted Dynamic Client Registration
        AccessTokenResponse response = udapClientService.getAccessToken(defaultAuthorizationServer,
                expectedMetadataIssuer, authZExtensionList, false);

        assertTrue(true);
    }

    // @Test
    // @Order(3)
    void searchPatient() throws ParseException {

        PatientSearchService.searchPatient("yoida");

        assertTrue(true);
    }

}
