# hsm_sim — HSM Simulator

A gRPC server that simulates an HSM (Hardware Security Module) for test and development
environments. It implements the `gematik.zetaguard.hsmproxy.v1` protocol with
deterministic, HKDF-derived keys so that any `key_id` “just works” without provisioning.

## Required dependencies

- openssl (debian: libssl-dev)
- protoc (debian: protobuf-compiler)
- core protobuf protos (debian: libprotobuf-dev)

Contains copies of some googleapis protos, see `proto/google/README` for source.

## RPCs

| RPC | Purpose | Key derivation |
|-----|---------|----------------|
| **Sign** | ECDSA signature (P1363 format) | EC key from `key_id` via HKDF |
| **GetPublicKey** | PEM, DER, JWK | EC key from `key_id` via HKDF |
| **GetCertificate** | X.509 leaf + chain | EC key from `key_id`, signed by CA |
| **Encrypt** | AES-256-GCM envelope encryption | AES key from `key_id` via HKDF |
| **Decrypt** | AES-256-GCM decryption | AES key from `key_id` via HKDF |
| **HealthCheck** | Liveness probe | — |
| **grpc.health.v1/Check** | Standard gRPC health probe (k8s native) | — |

## Key derivation

**Asymmetric** (Sign, GetPublicKey, GetCertificate): the `key_id` must end with a curve
suffix — `.p256`, `.p384`, or `.p521`. The EC private key scalar is derived
deterministically via HKDF-SHA256 on the `key_id`. Same `key_id` always produces the
same key.

**Symmetric** (Encrypt, Decrypt): any `key_id` works. A 256-bit AES key is derived via
HKDF-SHA256. Same `key_id` for encrypt and decrypt yields the same key automatically.

**Certificates**: leaf certs are generated on the fly, signed by a CA from
`keys/ca.{key,crt}`. Fixed validity: `notBefore` = Unix epoch, `notAfter` = 2337-01-01.
Serial derived from `key_id`.

Derived keys and certificates are cached on disk in the keys directory to avoid repeated
generation.

## Usage

```sh
# Local development (listens on [::1]:50051 by default)
cargo run -p hsm_sim

# Custom listen address and keys directory
cargo run -p hsm_sim -- --listen 0.0.0.0:50051 --keys-dir /path/to/keys

# Keys directory can also be set via environment variable
HSM_SIM_KEYS=/path/to/keys cargo run -p hsm_sim
```

### gRPC reflection

The server exposes gRPC server reflection, so you can explore with `grpcurl`:

```sh
grpcurl -plaintext '[::1]:50051' list
grpcurl -plaintext '[::1]:50051' describe gematik.zetaguard.hsmproxy.v1.HsmProxyService
grpcurl -plaintext -d '{"key_id": "my-key.p256"}' \
  '[::1]:50051' gematik.zetaguard.hsmproxy.v1.HsmProxyService/GetPublicKey
```

See the test for usage examples and expectations for all endpoints.
