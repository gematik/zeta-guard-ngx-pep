# Generating keys and certificates

Generate an ECDSA key:
```shell
openssl ecparam -name prime256v1 -genkey -noout -out subject_key.pem
```
Alternatively use `brainpoolP256r1` or any other supported by `openssl ecparam -list_curves`. 

Generate a CSR:
```shell
openssl req -out subject_csr.pem -key subject_key.pem -new -subj /CN=subject
```

For CAs create a self-signed certificate:
```shell
openssl req -out issuer_cert.pem -key issuer_key.pem -new -x509 -days 3560 -subj /CN=issuer
```

Sign a CSR with a CA certificate and key, and ocsp extension:
```shell
openssl x509 -req -CA issuer_cert.pem -CAkey issuer_key.pem -in subject_csr.pem -out subject_cert.pem -days 3650 -extfile ocsp_extension.cfg
```

For cross-signing CAs:
```shell
openssl x509 -req -CA ca1_cert.pem -CAkey ca1_key.pem -in ca2_csr.pem -out ca2_by_ca1_cert.pem -days 3650 -extfile cross_extension.cfg
```


# Setup of roots.json

The roots.json file is an array of root ca certificates in ascending order, where the first entry is the oldest CA and
the last entry the newest. Each entry is a JSON object containing a self-signed certificate and associated metadata,
as well as cross-certificates for the next and previous entry certificate. The first entry has no previous
cross-certificate, while the last entry has no next one; the respective JSON values are an empty string.

```json
[
  ...
  {
    "cert": "self signed certificate, in DER+base64 encoding",
    "cn":   "The common name component of the cert subject, e.g. GEM.RCA3",
    "name": "name of this entry, based on cn but without authority prefix, e.g. RCA3",
    "next": "next entry cert, but cross-signed by this cert, in DER+base64 encoding",
    "nva":  "not valid after date from cert in RFC 3339 format, eg. 2027-08-09T08:38:45",
    "nvb":  "not valid before date from cert in RFC 3339 format",
    "prev": "previous entry cert, but cross-signed by this cert, in DER+base64 encoding",
    "ski":  "subject key identifier of cert, as lowercase hex"
  },
  ...
]
```

To create a fake roots.json, follow these steps:

- create self-signed ca1, ca2, ca3, ...
- create csr for each ca
- create next cross signed ca2 by ca1, ca3 by ca2, ...
- create previous cross signed ca1 by ca2, ca2 by ca3, ...

