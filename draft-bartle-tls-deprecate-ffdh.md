---
title: Deprecating FFDH Ciphersuites in TLS
abbrev: Deprecating FFDH
docname: draft-bartle-tls-deprecate-ffdh-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

informative:
  Raccoon:
    title: "Raccoon Attack: Finding and Exploiting Most-Significant-Bit-Oracles in TLS-DH(E)"
    target: https://raccoon-attack.com/RacoonAttack.pdf
    date: 2020-09-09
    author:
      - ins: R. Merget
      - ins: M. Brinkmann
      - ins: N. Aviram
      - ins: J. Somorovsky
      - ins: J. Mittmann
      - ins: J. Schwenk
  ICA:
    title: "Practical invalid curve attacks on TLS-ECDH"
    target: https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.704.7932&rep=rep1&type=pdf
    date: 2015-09-21
    author:
      - ins: T. Jager
      - ins: J. Schwenk
      - ins: J. Somorovsky

author:
 -
       ins: C. Bartle
       name: Carrick Bartle
       organization: Apple, Inc.
       email: cbartle@apple.com

 -
       ins: N. Aviram
       name: Nimrod Aviram
       organization:
       email: nimrod.aviram@gmail.com

 -
       ins: F. Valsorda
       name: Filippo Valsorda
       organization:
       email: ietf@filippo.io

--- abstract

This document deprecates the use of finite field Diffie Hellman cipher suites
and discourages the use of elliptic curve Diffie Hellman cipher suites, both of
which have known vulnerabilities or improper security properties when implemented
incorrectly.

--- middle

# Introduction

TLS supports a variety of key exchange algorithms, including those based
on finite field and elliptic curve Diffie Hellman (DH) groups. Each of these
also come in ephemeral and non-ephemeral varieties. Non-ephemeral DH algorithms
use static DH public keys included in the authenticating peer's certificate;
see {{?RFC4492}} for discussion. In contrast, ephemeral DH algorithms use ephemeral
DH public keys sent in the handshake and authenticated by the peer's certificate.
Ephemeral and non-ephemeral finite field DH algorithms are called DHE and DH,
respectively, and ephemeral and non-ephemeral elliptic curve DH algorithms are called
ECDHE and ECDH, respectively {{?RFC4492}}.

In general, non-ephemeral cipher suites are not recommended due to their lack of
forward secrecy. However, as demonstrated by the {{Raccoon}} attack on finite-field
DH, public key reuse, either via non-ephemeral cipher suites or reused keys with
ephemeral cipher suites, can lead to timing side channels that may leak connection
secrets. For elliptic curve DH, invalid curve attacks broadly follow the same
pattern, where a long-lived secret is extracted using side channels {{ICA}},
further demonstrating the security risk of reusing public keys. While both side
channels can be avoided in implementations, experience shows that in practice,
implementations may fail to thwart such attacks due to the complexity of the
required mitigations.

Given these problems, this document updates {{!RFC4346}}, {{!RFC5246}}, {{!RFC4162}},
{{!RFC6347}}, {{!RFC5932}}, {{!RFC5288}}, {{!RFC6209}}, {{!RFC6367}}, {{!RFC8422}},
{{!RFC5289}}, and {{!RFC5469}} to deprecate cipher suites with key reuse, prohibiting
and discouraging their use.

## Requirements

{::boilerplate bcp14}

# Non-Ephemeral Diffie Hellman {#non-ephemeral}

Clients MUST NOT offer non-ephemeral DH cipher suites in TLS 1.2 connections. (Note that
TLS 1.0 and 1.1 are deprecated by {{!RFC8996}}.) This includes all cipher suites listed
in the following table.

| Ciphersuite  | Reference |
|:-|:-|
| TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DH_DSS_WITH_DES_CBC_SHA | {{!RFC5469}} |
| TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DH_RSA_WITH_DES_CBC_SHA | {{!RFC5469}} |
| TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 | {{!RFC4346}}{{RFC6347}} |
| TLS_DH_anon_WITH_RC4_128_MD5 | {{!RFC5246}}{{RFC6347}} |
| TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA | {{!RFC4346}} |
| TLS_DH_anon_WITH_DES_CBC_SHA | {{!RFC5469}} |
| TLS_DH_anon_WITH_3DES_EDE_CBC_SHA | {{!RFC5246}} |
| TLS_DH_DSS_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_128_CBC_SHA | {{!RFC5246}} |
| TLS_DH_DSS_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_256_CBC_SHA | {{!RFC5246}} |
| TLS_DH_DSS_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA | {{!RFC5932}} |
| TLS_DH_DSS_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_RSA_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_128_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_anon_WITH_AES_256_CBC_SHA256 | {{!RFC5246}} |
| TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA | {{!RFC5932}} |
| TLS_DH_DSS_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DH_RSA_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DH_anon_WITH_SEED_CBC_SHA | {{!RFC4162}} |
| TLS_DH_RSA_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DH_RSA_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DH_DSS_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DH_DSS_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DH_anon_WITH_AES_128_GCM_SHA256 | {{!RFC5288}} |
| TLS_DH_anon_WITH_AES_256_GCM_SHA384 | {{!RFC5288}} |
| TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 | {{!RFC5932}} |
| TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |

Clients SHOULD NOT offer non-ephemeral ECDH cipher suites in TLS 1.2
connections. (Note that TLS 1.0 and 1.1 are deprecated by {{!RFC8996}}.) This
includes all cipher suites listed in the following table.

| Ciphersuite  | Reference |
|:-|:-|
| TLS_ECDH_ECDSA_WITH_NULL_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_RC4_128_SHA | {{!RFC8422}}{{RFC6347}} |
| TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_NULL_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_RC4_128_SHA | {{!RFC8422}}{{RFC6347}} |
| TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_AES_128_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_RSA_WITH_AES_256_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_NULL_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_RC4_128_SHA | {{!RFC8422}}{{RFC6347}} |
| TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_AES_128_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_anon_WITH_AES_256_CBC_SHA | {{!RFC8422}} |
| TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 | {{!RFC5289}} |
| TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 | {{!RFC5289}} |
| TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 | {{!RFC6209}} |
| TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 | {{!RFC6209}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC6367}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 | {{!RFC6367}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 | {{!RFC6367}} |
| TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 | {{!RFC6367}} |

# Ephemeral Diffie Hellman

Clients and servers MUST NOT reuse ephemeral DHE or ECDHE public keys across
TLS connections for all existing (and future) TLS versions. Doing so invalidates
forward secrecy properties of these connections. In the case of DHE (finite field
DH) cipher suites, such reuse may also lead to vulnerabilities such as those
used in the {{Raccoon}} attack. See {{sec-considerations}} for related discussion.

# IANA Considerations

This document makes no requests to IANA. All cipher suites listed in {{non-ephemeral}}
are already marked as not recommended in the "TLS Cipher Suites" registry.

# Security Considerations {#sec-considerations}

Non-ephemeral finite field DH cipher suites (TLS_DH_\*), as well as ephemeral key reuse
for finite field DH cipher suites, are prohibited due to the {{Raccoon}} attack. Both are
already considered bad practice since they do not provide forward secrecy. However,
Raccoon revealed that timing side channels in processing TLS premaster secrets may be
exploited to reveal the encrypted premaster secret.

For non-ephemeral elliptic curve DH cipher suites, invalid curve attacks
similarly exploit side channels to extract the secret from a long-lived public
key. These attacks have been shown to be practical against real-world TLS
implementations {{ICA}}. Therefore, this document discourages the reuse of elliptic
curve DH public keys.

# Acknowledgments

This document was inspired by discussion on the TLS WG mailing list and
a suggestion by Filippo Valsorda following the release of the {{Raccoon}} attack. Thanks
to Christopher A. Wood for writing up the initial draft of this document.
