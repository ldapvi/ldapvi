# Integration Tests

End-to-end tests for ldapvi against a real LDAP server running in Docker.

## Prerequisites

- Docker
- Rust toolchain
- ldapvi and test-ldapvi built (run `make` and `make test-ldapvi` in `../ldapvi/`)

## LDAP backends

Two Dockerfiles provide identical LDAP databases (suffix `dc=example,dc=com`,
root DN `cn=admin,dc=example,dc=com`, password `secret`) seeded with a test
user:

| Backend | Dockerfile | Image tag |
|---------|------------|-----------|
| OpenLDAP (slapd) | `Dockerfile.slapd` | `ldapvi-test-slapd` |
| 389 Directory Server | `Dockerfile.389ds` | `ldapvi-test-389ds` |

## Running the tests

### OpenLDAP (default)

```sh
docker build -t ldapvi-test-slapd -f Dockerfile.slapd .
cargo test
```

### 389 Directory Server

```sh
docker build -t ldapvi-test-389ds -f Dockerfile.389ds .
LDAPVI_TEST_IMAGE=ldapvi-test-389ds cargo test
```

The `LDAPVI_TEST_IMAGE` environment variable selects which Docker image to
use.  When unset it defaults to `ldapvi-test-slapd`.
