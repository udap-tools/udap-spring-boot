package org.udap.client.demo.tefca;

import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.hl7.fhir.r4.model.Enumerations.AdministrativeGender;
import org.hl7.fhir.r4.model.Patient;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.parser.IParser;
import ca.uhn.fhir.rest.client.api.IGenericClient;

/**
 * Scratch code to be used at TEFCA Project-a-Thon: March 8-9, 2023
 *
 * @author Brett P Stringham
 *
 */
public final class PatientSearchService {

    PatientSearchService() {

    }

    static final SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-M-dd");

    public static String searchPatient(String serverBase) throws ParseException {
        FhirContext ctx = FhirContext.forR4();

        IGenericClient client = ctx.newRestfulGenericClient(serverBase);

        /*
         * TODO: Pull patient information from test file
         */
        Patient patient = new Patient();
        patient.setBirthDate(dateFormatter.parse("1970-05-01"))
            .setGender(AdministrativeGender.FEMALE)
            .addName()
            .setFamily("Demo")
            .addGiven("Demo");

        // Instantiate a new JSON parser
        IParser parser = ctx.newJsonParser();

        // Serialize it
        return parser.encodeResourceToString(patient);

        /**
         *
         * // Perform a search Bundle results = client .search()
         * .forResource(Patient.class) .where(Patient.FAMILY.matches().value("duck"))
         * .returnBundle(Bundle.class) .execute();
         *
         * System.out.println("Found " + results.getEntry().size() + " patients named
         * 'duck'");
         *
         **/
    }

}
