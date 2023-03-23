# UDAP Client Service - Springboot
	- Current state: Simplistic UDAP Client for b2b scenarios to get the ball rolling
	- Target state: UDAP client - Spring Boot Starter
	

# Getting Started
- To leverage the UDAP Test Tool, you must be issued a "UDAP Test Certificate NOT FOR USE WITH PHI" for your FHIR CLIENT APP
- https://www.udap.org/UDAPTestTool/

# Environment Setup

The values shown below are examples. Set the according to your development environment setup (e.g., Eclipse Run or Debug Configurations)

```console
# If FHIR CLIENT is already registered
UDAP_DEMO_FHIR_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-0123456789

# Example FHIR Client App - Properties from issued x509 
UDAP_DEMO_FHIR_CLIENT_INTEGRATION_TEST_X509_PRINCPLE_NAME_EXPECTED=CN=https://sandbox.udap.org/client-apps/abc-app-developer,OU=UDAP Test Certificate NOT FOR USE WITH PHI,O=ABC Developer (self asserted)
UDAP_DEMO_FHIR_CLIENT_INTEGRATION_TEST_X509_SAN_EXPECTED=https://sandbox.udap.org/client-apps/abc-app-developer
UDAP_DEMO_FHIR_CLIENT_PRIVATE_KEY_LOCATION=file:/home/<user>/.udap/udap-sandbox-abc-developer.p12
UDAP_DEMO_FHIR_CLIENT_PRIVATE_KEY_SECRET=************
UDAP_DEMO_FHIR_CLIENT_X509_LOCATION=file:/home/<user>/.udap/udap-sandbox-abc-developer.crt
```

# UDAP Client (Spring Boot) - B2B (client credentials grant)
WIP (Tested a recent connectathons in B2B scenarios)

# UDAP Server (Spring Boot)
Planned

## What does it support
The repository contains components and example uses to support the following items from [Security for Scalable Registration, Authentication, and Authorization](http://hl7.org/fhir/us/udap-security/).  The intent is to also support generic UDAP, but the driving force currently is supporting auto registration to FHIR® servers.  FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7

| Feature   | Sub Feature             | Supported           | Comments                                               |
|-------------------------|---|---------------------|--------------------------------------------------------|
| Client                  | | Started         | Happy path discovery, server metadata verification, and trusted DCR |
| [Discovery](http://hl7.org/fhir/us/udap-security/discovery.html) || ✔️  | **PLANNED** [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities) |
| [Registration](http://hl7.org/fhir/us/udap-security/registration.html)|| ✔️ | **PLANNED** [Multi Trust Communities](http://hl7.org/fhir/us/udap-security/discovery.html#multiple-trust-communities)|  |
||Inclusion of Certifications and Endorsements|Planned||

### Authorization and Authentication 
| Feature   | Sub Feature             | Supported           | Comments                                               |
|-------------------------|---|---------------------|--------------------------------------------------------|
| [Consumer-Facing](http://hl7.org/fhir/us/udap-security/consumer.html)|| Not Started | |
| [Business-to-Business](http://hl7.org/fhir/us/udap-security/b2b.html)|| ✔️ | Works with client_credentials only and [FUTURE] authorization_code flows. |
||JWT Claim Extensions|Started|Some work completed for the B2B Authorization Extension (hl7-b2b) extension|  
| [Tiered OAuth for User Authentication](http://hl7.org/fhir/us/udap-security/user.html) || Not Started | |

# UDAP Test Tool

https://www.udap.org/UDAPTestTool/
 
## Test 3: Trusted dynamic client registration
1. FHIR Client examines FHIR sever for trustworthiness
	- Client application retrieves metadata from the following [FHIR server - Base URL](https://test.udap.org/fhir/r4/stage)
2. FHIR Client performs JWT validation and evalutation to assert trustworthiness
	- If FHIR server is considered trusted, FHIR client (this app) performs UDAP Trusted Dynamic Client registration at FHIR Servers registration endpoint
	- FHIR client submits a software statement signed with the private key corresponding to the app's UDAP test certificate

## Test 9: JWT-Based Client Authentication (client credentials flow)
Test 9: JWT-Based Client Authentication (client credentials flow)

FHIR Base URL: https://test.udap.org/fhir/r4/stage