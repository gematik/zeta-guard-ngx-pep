<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes ZETA PEP

## Release 0.4.0

### added:
- openvex-based CVE management
- structured errors:
  - ZETA/high-level errors as application/json (schema: zeta-error.yaml)
  - embedded html error pages for long-form descriptions
  - pass errors on the ASL channel as application/cbor to the caller (type: ErrorResponse)
- ASL
  - certificate config (`pep_asl_*` options)
  - /CertData endpoint

### changed:
- switch to custom nginx build to not be constrained by ngx/vendored and to allow usage
  of nginxinc/nginx-unprivileged base images
- dependency upgrades, notable:
  - Rust 1.94.0
  - nginx 1.29.5
  - ngx-tickle 0.2.0
- sync JSON schemas from gematik/zeta for VSDM2-interop
  - client-data.yaml: ZETA-Client-Data upstream header
  - zeta-user-info.yaml: ZETA-User-Info upstream header
- trim unneeded dependencies from prod. images as part of ongoing CVE mitigations

## Release 0.3.0

### added:
- Implement integration test harness with code coverage measurements
  This re-uses client functionality of the purl utility, which has been extracted to the
  new client module. purl is now a subpackage in the workspace due to crate type
  requirements.

### changed:
- Ensure ZETA-API-Version header is set early, so it is always emitted in error cases
- Added default ports for ws (80) and wss (443) for url normalization (relevant for DPoP
  token verification)
- Compile against nginx 1.28.1, upgrade rust to 1.92, and use trixie-based nginx image
  (from bookworm)
- Update client code to extract AdmissionSyntax from SMC-B certificate, pass telematik-id
  to token exchange and provide client-self-assessment, client_statement, and attestation
  challenge (IT, purl)

## Release 0.2.5

### changed:
- full implementation of ASL test mode (see A_26942 and A_26943)

## Release 0.2.4

### added:
- url normalization for htu verification
- added htu verification again
- extracting userdata and clientdata from access token and passing it on to the Fachdienst

### changed:
- minor build and CI changes

## Release 0.2.3

### changed:
- removed htu verification due to problems with the test setup

## Release 0.2.2

### added:
- PoPP token verification

## Release 0.2.1

### added:
- DPoP Verification and enforcement

## Release 0.2.0

### added:
- token verification as per spec
- Passing user and client information onto the Fachdienst via headers
  - **warning** still contains some mock data
- ASL implementation
  - **warning** not ready for production use yet


## Release 0.1.3

### added:
- Prototype of the ZETA PEP added
