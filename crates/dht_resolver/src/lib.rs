//! # dht_resolver — in-network addressing over a Kademlia DHT
//!
//! Turnet resolves human-readable names (`myhandle.tur`) to the 64-bit
//! cryptographic Node IDs that identify relay nodes, **without** any
//! centralized DNS registry. The backbone is a `libp2p` Kademlia DHT; this
//! crate owns the name→NodeID record format and the resolve/announce API.
//!
//! ## Modules
//! - [`resolver`]  — map a `.tur` name to live [`NodeId`]s (anycast-aware).
//! - [`anycast`]   — multi-node mirror routing across identical replicas.
//! - [`claim`]     — anti-squatting: lock a `.tur` handle by proving control
//!   of the matching legacy clear-web domain's TLS certificate. The X.509
//!   chain validation, DNS-name matching, and Ed25519 proof-of-possession
//!   are implemented and tested; a zero-knowledge wrapper (prove the claim
//!   without revealing the certificate) is future work.
//!
//! `libp2p` is wired in as the transport/DHT dependency; the Kademlia
//! behaviour, swarm wiring, and record validation are scaffold stubs.

#![forbid(unsafe_code)]

use thiserror::Error;

/// A 64-bit cryptographic node identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

impl NodeId {
    /// Render as zero-padded hex, the canonical wire form.
    pub fn to_hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

/// Errors from name resolution and record handling.
#[derive(Debug, Error)]
pub enum DhtError {
    #[error("not implemented in scaffold: {0}")]
    NotImplemented(&'static str),
    #[error("name not found in dht")]
    NotFound,
    #[error("invalid turnet name: {0}")]
    InvalidName(String),
}

/// Normalize and validate a Turnet name, returning the lookup key.
///
/// Rejects empty labels and names whose final label is not a Turnet TLD.
pub fn normalize_name(name: &str) -> Result<String, DhtError> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.split('.').any(|l| l.is_empty()) {
        return Err(DhtError::InvalidName(name));
    }
    match name.rsplit('.').next() {
        Some("tur") | Some("vps") | Some("cpt") => Ok(name),
        _ => Err(DhtError::InvalidName(name)),
    }
}

/// Name resolution against the DHT.
pub mod resolver {
    use super::{DhtError, NodeId};

    /// Handle to a running DHT resolver task.
    pub struct Resolver;

    impl Resolver {
        /// Look up the live Node IDs currently serving `name`.
        ///
        /// Stub: returns [`DhtError::NotImplemented`] until the Kademlia
        /// behaviour is wired to the swarm.
        pub async fn resolve(&self, _name: &str) -> Result<Vec<NodeId>, DhtError> {
            Err(DhtError::NotImplemented("kademlia resolve"))
        }

        /// Announce that this node serves `name`.
        pub async fn announce(&self, _name: &str, _node: NodeId) -> Result<(), DhtError> {
            Err(DhtError::NotImplemented("kademlia announce"))
        }
    }
}

/// Mesh anycast: balance a name across identical microVM replicas.
pub mod anycast {
    use super::{DhtError, NodeId};

    /// Pick a replica for a name given a set of healthy candidates.
    ///
    /// The policy here is deliberately simple and **deterministic**: the
    /// numerically smallest [`NodeId`] wins. A deterministic choice means every
    /// resolver that sees the same healthy set routes a given name to the same
    /// replica, which keeps a name's traffic affine to one mirror without any
    /// coordination. Latency-, load-, and hash-ring-aware selection (so that
    /// different names spread across mirrors) is a later milestone that will
    /// take richer per-candidate inputs than this signature carries.
    ///
    /// Returns [`DhtError::NotFound`] when there are no candidates.
    pub fn select(candidates: &[NodeId]) -> Result<NodeId, DhtError> {
        candidates
            .iter()
            .copied()
            .min_by_key(|n| n.0)
            .ok_or(DhtError::NotFound)
    }
}

/// Anti-squatting handle claims backed by a legacy domain's TLS certificate.
///
/// A party that already controls the clear-web domain `acme.com` can lock the
/// `acme.tur` handle by presenting the domain's TLS certificate chain and
/// *signing a handle-binding challenge with the certificate's private key*.
/// Verification establishes three independent facts:
///
/// 1. **Chain validity** — the presented chain parses, every certificate is
///    within its validity window at the verification time, each certificate is
///    signed by the next, and the top of the chain is signed by a configured
///    trusted root. This is ordinary X.509 path validation (the same checks a
///    TLS client makes), done here with [`x509_parser`].
/// 2. **Domain coverage** — the leaf certificate is actually valid for
///    `legacy_domain`, via a `dNSName` Subject Alternative Name, with RFC 6125
///    single-label wildcard matching.
/// 3. **Possession** — the claimant signed [`claim_challenge`] (a
///    domain-separated binding of the handle to the legacy domain) with the
///    leaf certificate's key, proving they hold the private key rather than
///    merely replaying a public chain.
///
/// ### Scope and honest limitations
/// - **Key types:** possession proofs are verified for **Ed25519** leaf keys
///   (RFC 8410). RSA and ECDSA leaves are rejected with
///   [`ClaimError::UnsupportedKeyType`]; adding them is a mechanical dispatch
///   on the SubjectPublicKeyInfo algorithm and is deliberately out of scope
///   here rather than stubbed.
/// - **Trust roots** are supplied explicitly ([`TrustStore`]); wiring a
///   platform/CT-log root set is deployment configuration, not this crate's job.
/// - **Handle↔domain binding** uses a conservative label rule (see
///   [`HandleClaim::verify`]); a public-suffix-aware registrable-domain match
///   is a refinement.
/// - A **zero-knowledge** wrapper that proves all of the above without
///   revealing the certificate (the long-term design goal) builds on this
///   verifiable core and is future work.
pub mod claim {
    use super::normalize_name;
    use ring::signature;
    use thiserror::Error;
    use x509_parser::oid_registry::OID_SIG_ED25519;
    use x509_parser::prelude::*;

    /// Domain-separation tag for the handle-binding possession challenge.
    /// Bumped if the challenge encoding ever changes, so an old signature can
    /// never be reinterpreted under new rules.
    const CLAIM_DOMAIN_TAG: &[u8] = b"turnet-handle-claim-v1";

    /// Why a handle claim failed to verify.
    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum ClaimError {
        /// No certificates were presented.
        #[error("empty certificate chain")]
        EmptyChain,
        /// A certificate (or a trust-store root) could not be parsed.
        #[error("malformed certificate")]
        MalformedCertificate,
        /// A certificate was outside its validity window at the given time.
        #[error("certificate expired or not yet valid")]
        Expired,
        /// A link in the chain, or the link to a trusted root, did not verify.
        #[error("certificate chain does not link to a trusted root")]
        Untrusted,
        /// The leaf certificate is not valid for the claimed legacy domain.
        #[error("leaf certificate does not cover domain {0}")]
        DomainNotCovered(String),
        /// The handle does not correspond to the legacy domain.
        #[error("handle {handle} does not bind legacy domain {domain}")]
        HandleDomainMismatch {
            /// The claimed Turnet handle.
            handle: String,
            /// The legacy clear-web domain.
            domain: String,
        },
        /// The handle is not a syntactically valid Turnet name.
        #[error("invalid turnet handle: {0}")]
        InvalidHandle(String),
        /// The leaf key is not an Ed25519 key (see module docs).
        #[error("unsupported leaf key type (only Ed25519 is implemented)")]
        UnsupportedKeyType,
        /// The possession signature did not verify against the leaf key.
        #[error("possession proof did not verify")]
        BadPossessionProof,
    }

    /// A DER-encoded certificate chain: leaf first, then any intermediates,
    /// ordered so that each certificate is signed by the next one.
    pub struct CertChain {
        ders: Vec<Vec<u8>>,
    }

    impl CertChain {
        /// Build a chain from DER certificates, leaf first.
        pub fn new(ders: Vec<Vec<u8>>) -> Self {
            Self { ders }
        }
    }

    /// The set of trusted root certificates (DER) a chain must link up to.
    pub struct TrustStore {
        roots: Vec<Vec<u8>>,
    }

    impl TrustStore {
        /// Build a trust store from DER root certificates.
        pub fn new(roots: Vec<Vec<u8>>) -> Self {
            Self { roots }
        }
    }

    /// A request to lock a `.tur` handle against a legacy clear-web domain.
    pub struct HandleClaim {
        /// The handle being claimed, e.g. `acme.tur`.
        pub handle: String,
        /// The legacy domain whose TLS certificate backs the claim.
        pub legacy_domain: String,
    }

    /// The canonical bytes a claimant signs with the leaf certificate's key to
    /// prove possession: the domain tag followed by length-prefixed handle and
    /// legacy domain. Length prefixes make the encoding unambiguous so no two
    /// distinct (handle, domain) pairs ever share a challenge.
    pub fn claim_challenge(handle: &str, legacy_domain: &str) -> Vec<u8> {
        let mut v =
            Vec::with_capacity(CLAIM_DOMAIN_TAG.len() + handle.len() + legacy_domain.len() + 8);
        v.extend_from_slice(CLAIM_DOMAIN_TAG);
        for part in [handle, legacy_domain] {
            v.extend_from_slice(&(part.len() as u32).to_be_bytes());
            v.extend_from_slice(part.as_bytes());
        }
        v
    }

    impl HandleClaim {
        /// Verify this claim against `chain`, anchored at `trust`, as of the
        /// Unix time `now_unix`, with `possession_sig` over [`claim_challenge`].
        ///
        /// The handle↔domain binding rule is conservative: the handle must be a
        /// valid Turnet name whose leftmost label also appears as a DNS label
        /// of `legacy_domain` (so `acme.tur` binds `acme.com`). The
        /// authoritative gate is still the certificate's domain coverage plus
        /// the possession proof; the label rule only blocks obviously
        /// unrelated pairings.
        pub fn verify(
            &self,
            chain: &CertChain,
            trust: &TrustStore,
            now_unix: i64,
            possession_sig: &[u8],
        ) -> Result<(), ClaimError> {
            // 1. Handle must be a valid Turnet name bound to the legacy domain.
            let handle = normalize_name(&self.handle)
                .map_err(|_| ClaimError::InvalidHandle(self.handle.clone()))?;
            let domain = self
                .legacy_domain
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !handle_binds_domain(&handle, &domain) {
                return Err(ClaimError::HandleDomainMismatch { handle, domain });
            }

            // 2. Parse the chain (leaf first) and the trust time.
            if chain.ders.is_empty() {
                return Err(ClaimError::EmptyChain);
            }
            let now = ASN1Time::from_timestamp(now_unix).map_err(|_| ClaimError::Expired)?;
            let parsed = chain
                .ders
                .iter()
                .map(|der| X509Certificate::from_der(der).map(|(_, c)| c))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ClaimError::MalformedCertificate)?;

            // 3. Every presented certificate must be inside its validity window.
            if parsed.iter().any(|c| !c.validity().is_valid_at(now)) {
                return Err(ClaimError::Expired);
            }

            // 4. Each certificate must be signed by the next one in the chain.
            for pair in parsed.windows(2) {
                pair[0]
                    .verify_signature(Some(pair[1].public_key()))
                    .map_err(|_| ClaimError::Untrusted)?;
            }

            // 5. The top of the chain must be signed by a *currently valid*
            //    trusted root.
            let top = parsed.last().expect("non-empty chain checked above");
            let trusted =
                trust
                    .roots
                    .iter()
                    .any(|root_der| match X509Certificate::from_der(root_der) {
                        Ok((_, root)) => {
                            root.validity().is_valid_at(now)
                                && top.verify_signature(Some(root.public_key())).is_ok()
                        }
                        Err(_) => false,
                    });
            if !trusted {
                return Err(ClaimError::Untrusted);
            }

            // 6. The leaf must actually be valid for the legacy domain.
            let leaf = &parsed[0];
            if !leaf_covers_domain(leaf, &domain)? {
                return Err(ClaimError::DomainNotCovered(domain));
            }

            // 7. Possession: the claimant signed the binding with the leaf key.
            verify_possession(leaf, &claim_challenge(&handle, &domain), possession_sig)
        }
    }

    /// The handle's leftmost label must appear as a DNS label of the legacy
    /// domain (both lowercased). Conservative but never the sole security gate.
    fn handle_binds_domain(handle: &str, domain: &str) -> bool {
        let Some(label) = handle.split('.').next() else {
            return false;
        };
        !label.is_empty() && domain.split('.').any(|l| l == label)
    }

    /// True if the leaf certificate carries a `dNSName` SAN matching `domain`,
    /// honoring a single leading-label wildcard (RFC 6125).
    fn leaf_covers_domain(leaf: &X509Certificate, domain: &str) -> Result<bool, ClaimError> {
        let san = match leaf
            .subject_alternative_name()
            .map_err(|_| ClaimError::MalformedCertificate)?
        {
            Some(san) => san,
            None => return Ok(false),
        };
        Ok(san.value.general_names.iter().any(|gn| match gn {
            GeneralName::DNSName(pattern) => dns_name_matches(pattern, domain),
            _ => false,
        }))
    }

    /// RFC 6125 name matching with a single leftmost-label wildcard:
    /// `*.example.com` matches exactly one label (`a.example.com`) but not
    /// `example.com` and not `a.b.example.com`.
    fn dns_name_matches(pattern: &str, host: &str) -> bool {
        let pattern = pattern.to_ascii_lowercase();
        let host = host.to_ascii_lowercase();
        match pattern.strip_prefix("*.") {
            Some(suffix) => match host.split_once('.') {
                Some((label, rest)) => !label.is_empty() && rest == suffix,
                None => false,
            },
            None => pattern == host,
        }
    }

    /// Verify a possession signature against the leaf certificate's Ed25519 key.
    fn verify_possession(
        leaf: &X509Certificate,
        message: &[u8],
        sig: &[u8],
    ) -> Result<(), ClaimError> {
        let spki = leaf.public_key();
        if spki.algorithm.algorithm != OID_SIG_ED25519 {
            return Err(ClaimError::UnsupportedKeyType);
        }
        let key = spki.subject_public_key.data.as_ref();
        signature::UnparsedPublicKey::new(&signature::ED25519, key)
            .verify(message, sig)
            .map_err(|_| ClaimError::BadPossessionProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_hex_is_padded() {
        assert_eq!(NodeId(0xABCD).to_hex(), "000000000000abcd");
    }

    #[test]
    fn normalize_accepts_turnet_names() {
        assert_eq!(
            normalize_name("Shop.Example.TUR.").unwrap(),
            "shop.example.tur"
        );
    }

    #[test]
    fn normalize_rejects_clear_web() {
        assert!(normalize_name("example.com").is_err());
        assert!(normalize_name("").is_err());
    }

    #[test]
    fn anycast_empty_is_not_found() {
        assert!(matches!(anycast::select(&[]), Err(DhtError::NotFound)));
    }

    #[test]
    fn anycast_is_deterministic_and_order_independent() {
        let a = NodeId(0x30);
        let b = NodeId(0x10);
        let c = NodeId(0x20);
        // Smallest NodeId wins regardless of input ordering.
        assert_eq!(anycast::select(&[a, b, c]).unwrap(), b);
        assert_eq!(anycast::select(&[c, a, b]).unwrap(), b);
        assert_eq!(anycast::select(&[b]).unwrap(), b);
    }
}

#[cfg(test)]
mod claim_tests {
    use super::claim::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ED25519,
    };
    use ring::signature::Ed25519KeyPair;
    use rustls_pki_types::PrivatePkcs8KeyDer;

    /// A verification time safely inside every fixture's validity window.
    fn now_2026() -> i64 {
        date_time_ymd(2026, 6, 1).unix_timestamp()
    }

    /// A fresh Ed25519 key, as both an rcgen signer (for the certificate) and
    /// a ring key (for the possession proof), backed by the same secret.
    fn ed25519_keys() -> (KeyPair, Ed25519KeyPair) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let kp = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8.as_ref()),
            &PKCS_ED25519,
        )
        .unwrap();
        (kp, signer)
    }

    /// A test root CA that can issue leaf certificates.
    struct TestCa {
        params: CertificateParams,
        key: KeyPair,
        der: Vec<u8>,
    }

    impl TestCa {
        fn new() -> Self {
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let mut params = CertificateParams::new(vec!["Turnet Test Root".to_string()]).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.not_before = date_time_ymd(2020, 1, 1);
            params.not_after = date_time_ymd(2100, 1, 1);
            let der = params.self_signed(&key).unwrap().der().to_vec();
            Self { params, key, der }
        }

        fn issue(&self, sans: &[&str], not_after: (i32, u8, u8), leaf_key: &KeyPair) -> Vec<u8> {
            let mut params =
                CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                    .unwrap();
            params.not_before = date_time_ymd(2020, 1, 1);
            params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
            let issuer = Issuer::from_params(&self.params, &self.key);
            params.signed_by(leaf_key, &issuer).unwrap().der().to_vec()
        }
    }

    fn sign(signer: &Ed25519KeyPair, handle: &str, domain: &str) -> Vec<u8> {
        signer
            .sign(&claim_challenge(handle, domain))
            .as_ref()
            .to_vec()
    }

    /// A `not_after` well past every verification time used in these tests.
    const FAR_FUTURE: (i32, u8, u8) = (2099, 1, 1);

    #[test]
    fn valid_claim_verifies() {
        let ca = TestCa::new();
        let (leaf_key, signer) = ed25519_keys();
        let leaf = ca.issue(&["acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        let sig = sign(&signer, "acme.tur", "acme.com");
        assert_eq!(claim.verify(&chain, &trust, now_2026(), &sig), Ok(()));
    }

    #[test]
    fn wildcard_san_matches_one_label() {
        let ca = TestCa::new();
        let (leaf_key, signer) = ed25519_keys();
        let leaf = ca.issue(&["*.acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "api.acme.com".into(),
        };
        let sig = sign(&signer, "acme.tur", "api.acme.com");
        assert_eq!(claim.verify(&chain, &trust, now_2026(), &sig), Ok(()));
    }

    #[test]
    fn tampered_possession_is_rejected() {
        let ca = TestCa::new();
        let (leaf_key, signer) = ed25519_keys();
        let leaf = ca.issue(&["acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        let mut sig = sign(&signer, "acme.tur", "acme.com");
        sig[0] ^= 0x01;
        assert_eq!(
            claim.verify(&chain, &trust, now_2026(), &sig),
            Err(ClaimError::BadPossessionProof)
        );
    }

    #[test]
    fn possession_over_wrong_binding_is_rejected() {
        // A signature valid for a different handle must not transfer.
        let ca = TestCa::new();
        let (leaf_key, signer) = ed25519_keys();
        let leaf = ca.issue(&["acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        let sig = sign(&signer, "evil.tur", "acme.com");
        assert_eq!(
            claim.verify(&chain, &trust, now_2026(), &sig),
            Err(ClaimError::BadPossessionProof)
        );
    }

    #[test]
    fn untrusted_root_is_rejected() {
        let ca = TestCa::new();
        let other = TestCa::new();
        let (leaf_key, signer) = ed25519_keys();
        let leaf = ca.issue(&["acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        // Trust a *different* root than the one that signed the leaf.
        let trust = TrustStore::new(vec![other.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        let sig = sign(&signer, "acme.tur", "acme.com");
        assert_eq!(
            claim.verify(&chain, &trust, now_2026(), &sig),
            Err(ClaimError::Untrusted)
        );
    }

    #[test]
    fn domain_not_covered_is_rejected() {
        let ca = TestCa::new();
        let (leaf_key, signer) = ed25519_keys();
        // Certificate is for acme.com, but the claim is for acme.net.
        let leaf = ca.issue(&["acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.net".into(),
        };
        let sig = sign(&signer, "acme.tur", "acme.net");
        assert_eq!(
            claim.verify(&chain, &trust, now_2026(), &sig),
            Err(ClaimError::DomainNotCovered("acme.net".into()))
        );
    }

    #[test]
    fn handle_not_bound_to_domain_is_rejected() {
        let ca = TestCa::new();
        let (leaf_key, _signer) = ed25519_keys();
        let leaf = ca.issue(&["acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "notacme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        assert!(matches!(
            claim.verify(&chain, &trust, now_2026(), &[]),
            Err(ClaimError::HandleDomainMismatch { .. })
        ));
    }

    #[test]
    fn expired_leaf_is_rejected() {
        let ca = TestCa::new();
        let (leaf_key, signer) = ed25519_keys();
        // Leaf expired in 2021, verified at 2026.
        let leaf = ca.issue(&["acme.com"], (2021, 1, 1), &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        let sig = sign(&signer, "acme.tur", "acme.com");
        assert_eq!(
            claim.verify(&chain, &trust, now_2026(), &sig),
            Err(ClaimError::Expired)
        );
    }

    #[test]
    fn empty_chain_is_rejected() {
        let trust = TrustStore::new(vec![TestCa::new().der]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        assert_eq!(
            claim.verify(&CertChain::new(vec![]), &trust, now_2026(), &[]),
            Err(ClaimError::EmptyChain)
        );
    }

    #[test]
    fn non_ed25519_leaf_is_unsupported() {
        let ca = TestCa::new();
        // Default rcgen key is ECDSA P-256 — a valid TLS key we don't yet
        // verify possession for.
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = ca.issue(&["acme.com"], FAR_FUTURE, &leaf_key);
        let chain = CertChain::new(vec![leaf]);
        let trust = TrustStore::new(vec![ca.der.clone()]);
        let claim = HandleClaim {
            handle: "acme.tur".into(),
            legacy_domain: "acme.com".into(),
        };
        assert_eq!(
            claim.verify(&chain, &trust, now_2026(), &[0u8; 64]),
            Err(ClaimError::UnsupportedKeyType)
        );
    }

    #[test]
    fn challenge_is_domain_separated_and_unambiguous() {
        let c = claim_challenge("acme.tur", "acme.com");
        assert!(c.starts_with(b"turnet-handle-claim-v1"));
        // Length-prefixing prevents a boundary-shift collision.
        assert_ne!(
            claim_challenge("acme.tura", "cme.com"),
            claim_challenge("acme.tur", "acme.com")
        );
    }
}
