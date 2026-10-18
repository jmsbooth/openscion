//! Deterministic PUBLIC-TEST-KEY fixture exporter for cross-language checks.
//! This example does not expose or use production credentials and cannot
//! promote a protected channel. Never install its signing seed in production.
use ed25519_dalek::{Signer, SigningKey};
use openscion_evidence_verifier_lab::*;

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(value.len() * 2);
    for byte in value {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn main() {
    const SUBJECT: &str = "agent01";
    const ISSUER_KEY_ID: &str = "review-key-01";
    const AUDIENCE: &str = "openscion.authority.local.v1";
    const EVIDENCE: &[u8] = b"FOSS-478-test-evidence-bundle";
    let signer = SigningKey::from_bytes(&[7u8; 32]);
    let policy_digest = sha256(b"FOSS-478-test-policy");
    let evidence_digest = sha256(EVIDENCE);
    let request = PromotionRequest {
        channel: "main".into(),
        expected_head: None,
        candidate: format!("r1_{}", "a".repeat(64)),
        policy_id: "policy-foss478".into(),
        policy_digest,
        policy_epoch: 3,
        evidence_digest,
        idempotency_key: "stable-idempotency-key-01".into(),
    };
    let fingerprint = request.fingerprint(SUBJECT).expect("valid fixed fixture");
    let signed = AuthorizationStatement {
        audience: AUDIENCE.into(),
        issuer_key_id: ISSUER_KEY_ID.into(),
        issuer_key_version: 2,
        algorithm: ALG_ED25519,
        request_fingerprint: fingerprint,
        channel: request.channel.clone(),
        expected_head: None,
        candidate: request.candidate.clone(),
        policy_id: request.policy_id.clone(),
        policy_digest,
        policy_epoch: request.policy_epoch,
        evidence_digest,
        key_epoch: 7,
        revocation_epoch: 11,
        role: Role::Reviewer,
        decision: DECISION_ALLOW,
        nonce: [9u8; 32],
        issued_at: 1_799_999_970,
        expires_at: 1_800_000_300,
    };
    let wire = signed.encode_canonical();
    let signature = signer.sign(&wire).to_bytes();
    println!(
        concat!(
            "{{\n",
            "  \"format\": \"openscion.foss478.public-test-vector.v1\",\n",
            "  \"subject\": \"{}\",\n",
            "  \"channel\": \"{}\",\n",
            "  \"expected_head\": null,\n",
            "  \"candidate\": \"{}\",\n",
            "  \"policy_id\": \"{}\",\n",
            "  \"policy_epoch\": {},\n",
            "  \"idempotency_key\": \"{}\",\n",
            "  \"evidence_bundle_hex\": \"{}\",\n",
            "  \"policy_digest_hex\": \"{}\",\n",
            "  \"evidence_digest_hex\": \"{}\",\n",
            "  \"request_fingerprint_hex\": \"{}\",\n",
            "  \"audience\": \"{}\",\n",
            "  \"issuer_key_id\": \"{}\",\n",
            "  \"public_key_hex\": \"{}\",\n",
            "  \"signed_statement_hex\": \"{}\",\n",
            "  \"signature_hex\": \"{}\"\n",
            "}}\n"
        ),
        SUBJECT,
        request.channel,
        request.candidate,
        request.policy_id,
        request.policy_epoch,
        request.idempotency_key,
        hex(EVIDENCE),
        hex(&policy_digest),
        hex(&evidence_digest),
        hex(&fingerprint),
        AUDIENCE,
        ISSUER_KEY_ID,
        hex(&signer.verifying_key().to_bytes()),
        hex(&wire),
        hex(&signature),
    );
}
