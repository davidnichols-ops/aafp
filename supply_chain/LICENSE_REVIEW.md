# AAFP License Review

```
Document:         LICENSE_REVIEW.md
Date:             2025-01-15
Reviewer:         Automated + manual review
Scope:            All direct and transitive dependencies
```

## 1. Project License

The AAFP project is licensed under **MIT OR Apache-2.0** (dual
license, SPDX: `MIT OR Apache-2.0`).

This is a permissive dual license that allows downstream users to
choose either license. It is compatible with most dependency
licenses.

## 2. Rust Dependency Licenses

### 2.1 Direct Dependencies

| Crate | Version | License | Compatible |
|-------|---------|---------|------------|
| anyhow | 1.0.103 | MIT OR Apache-2.0 | Yes |
| bytes | 1.12.0 | MIT | Yes |
| clap | 4.6.1 | MIT OR Apache-2.0 | Yes |
| criterion | 0.5.1 | Apache-2.0 OR MIT | Yes |
| hex | 0.4.3 | MIT OR Apache-2.0 | Yes |
| serde | 1.0.228 | MIT OR Apache-2.0 | Yes |
| serde_json | 1.0.150 | MIT OR Apache-2.0 | Yes |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | Yes |
| thiserror | 1.0.69 | MIT OR Apache-2.0 | Yes |
| tokio | 1.52.3 | MIT | Yes |
| tokio-util | 0.7.18 | MIT | Yes |
| tracing | 0.1.44 | MIT | Yes |
| tracing-subscriber | 0.3.23 | MIT | Yes |
| pqcrypto-mldsa | 0.1.2 | MIT OR Apache-2.0 | Yes |
| pqcrypto-traits | 0.3.5 | MIT OR Apache-2.0 | Yes |

### 2.2 Key Transitive Dependencies

| Crate | Version | License | Compatible |
|-------|---------|---------|------------|
| pqcrypto-internals | 0.2.11 | MIT OR Apache-2.0 | Yes |
| paste | 1.0.15 | MIT OR Apache-2.0 | Yes |
| ring | 0.17.14 | MIT OR Apache-2.0 | Yes |
| rustls | 0.23.41 | Apache-2.0 OR MIT | Yes |
| aws-lc-rs | 1.17.0 | MIT OR Apache-2.0 | Yes |
| aws-lc-sys | 0.41.0 | MIT OR Apache-2.0 | Yes |
| quinn | 0.11.11 | MIT OR Apache-2.0 | Yes |
| curve25519-dalek | 4.1.3 | BSD-3-Clause | Yes |
| x25519-dalek | 2.0.1 | BSD-3-Clause | Yes |
| chacha20poly1305 | 0.10.1 | MIT OR Apache-2.0 | Yes |
| hkdf | 0.12.4 | MIT OR Apache-2.0 | Yes |
| hmac | 0.12.1 | MIT OR Apache-2.0 | Yes |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | Yes |
| getrandom | 0.2.17 / 0.3.4 | MIT OR Apache-2.0 | Yes |
| libc | 0.2.186 | MIT OR Apache-2.0 | Yes |
| cc | 1.2.65 | MIT OR Apache-2.0 | Yes |
| cmake | 0.1.58 | MIT OR Apache-2.0 | Yes |

### 2.3 Full License Inventory

All 238 external crates in Cargo.lock were checked. Every crate
uses one of:
- MIT
- MIT OR Apache-2.0
- Apache-2.0
- Apache-2.0 OR MIT
- BSD-3-Clause

**No copyleft licenses** (GPL, LGPL, AGPL) were found.
**No unusual or restrictive licenses** were found.

## 3. Go Dependency Licenses

The Go implementation has **zero external dependencies**. Only the
Go standard library is used, which is licensed under
**BSD-3-Clause** (Go license).

## 4. Compatibility Assessment

| License | Count | Compatible with MIT/Apache-2.0? |
|---------|-------|---------------------------------|
| MIT | ~40% | Yes (same license) |
| MIT OR Apache-2.0 | ~50% | Yes (same license) |
| Apache-2.0 OR MIT | ~5% | Yes (same license) |
| BSD-3-Clause | ~5% | Yes (permissive, compatible) |

**Result**: PASS. All dependency licenses are permissive and
compatible with the project's MIT OR Apache-2.0 license.

## 5. Notes

- The `aws-lc-sys` crate (transitive, via rustls) builds AWS-LC, a
  C cryptographic library. AWS-LC is licensed under MIT OR
  Apache-2.0, but it also includes code from BoringSSL (BSD-3-Clause
  / ISC / OpenSSL). The combined license is compatible with the
  project license.
- The `ring` crate includes code from BoringSSL and NIST, all under
  permissive licenses (BSD-style, ISC, OpenSSL).
- No dependencies use dual-license arrangements that would require
  special handling (e.g., GPL + commercial exception).

## 6. Conclusion

All dependency licenses are permissive and compatible with the
project's MIT OR Apache-2.0 license. No copyleft or restrictive
licenses were found. No license conflicts exist.
