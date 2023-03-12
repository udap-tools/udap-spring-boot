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
UDAP_DEMO_FHIR_CLIENT_INTEGRATION_TEST_X509_PRINCPLE_NAME_EXPECTED=CN=https://sandbox.udap.org/client-apps/brettstringham,OU=UDAP Test Certificate NOT FOR USE WITH PHI,O=Brett Stringham (self asserted)
UDAP_DEMO_FHIR_CLIENT_INTEGRATION_TEST_X509_SAN_EXPECTED=https://sandbox.udap.org/client-apps/brettstringham
UDAP_DEMO_FHIR_CLIENT_PRIVATE_KEY_LOCATION=file:/home/<user>/.udap/udap-sandbox-brettstringham-2.p12
UDAP_DEMO_FHIR_CLIENT_PRIVATE_KEY_SECRET=************
UDAP_DEMO_FHIR_CLIENT_X509_LOCATION=file:/home/<user>/.udap/udap-sandbox-brettstringham-2.crt
```

## Test 3: Trusted dynamic client registration
1. FHIR Client examines FHIR sever for trustworthiness
	- Client application retrieves metadata from the following [FHIR server - Base URL](https://test.udap.org/fhir/r4/stage)
2. FHIR Client performs JWT validation and evalutation to assert trustworthiness
	- If FHIR server is considered trusted, FHIR client (this app) performs UDAP Trusted Dynamic Client registration at FHIR Servers registration endpoint
	- FHIR client submits a software statement signed with the private key corresponding to the app's UDAP test certificate

## Test 9: JWT-Based Client Authentication (client credentials flow)
Test 9: JWT-Based Client Authentication (client credentials flow)

FHIR Base URL: https://test.udap.org/fhir/r4/stage