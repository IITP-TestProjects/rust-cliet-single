use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,          //Scalar::default()
};
use subtle::CtOption;
use subtle::Choice;
//use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha2::{Sha512, Digest};
use rand_chacha::ChaChaRng;
use rand_core::{SeedableRng, RngCore};

struct Commitment {
    pub R: RistrettoPoint,
}

struct Secret {
    pub r: Scalar,
}

pub struct Cosigners {
    pub_keys: Vec<RistrettoPoint>,
}

pub struct SignaturePart {
    pub s: Scalar,
}

impl Cosigners {
    pub fn new(pub_keys: Vec<RistrettoPoint>) -> Self {
        Self { pub_keys }
    }

    pub fn aggregate_public_key(&self) -> RistrettoPoint {
        self.pub_keys.iter().fold(RistrettoPoint::default(), |acc, pk| acc + pk)
    }

    pub fn aggregate_commit(&self, commits: &[Commitment]) -> RistrettoPoint {
        commits.iter().fold(RistrettoPoint::default(), |acc, c| acc + c.R)
    }

    pub fn aggregate_signature(
        &self,
        agg_commit: RistrettoPoint,        // R
        sig_parts: &[SignaturePart],       // s_i 집합
    ) -> Vec<u8> {                         // (R‖S‖mask)
        // 1. S = Σ s_i
        let agg_s = sig_parts
            .iter()
            .fold(Scalar::default(), |acc, p| acc + p.s);

        // 2. 집계 마스크(bit-mask): 활성 코사이너 1, 비활성 0
        //   여기서는 sig_parts 길이에 맞춰 모두 참여했다고 가정
        let mut mask = vec![0u8; (self.pub_keys.len() + 7) / 8];
        for i in 0..self.pub_keys.len() {
            mask[i / 8] |= 1 << (i % 8);
        }

        // 3. 직렬화: 32B R + 32B S + mask
        let mut sig = Vec::with_capacity(64 + mask.len());
        sig.extend_from_slice(agg_commit.compress().as_bytes()); // R
        sig.extend_from_slice(&agg_s.to_bytes());                // S
        sig.extend_from_slice(&mask);                            // mask
        sig
    }
}

fn compute_challenge(
    agg_commit_bytes: &[u8],
    agg_pk_bytes: &[u8],
    message: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(agg_commit_bytes);
    hasher.update(agg_pk_bytes);
    hasher.update(message);

    let hash_result = hasher.finalize(); // 64 bytes
    Scalar::from_bytes_mod_order_wide(&hash_result[..64].try_into().unwrap())
}

pub fn cosign(
    sk: &Scalar,
    secret_r: &Scalar,
    message: &[u8],
    aggregate_pk: &RistrettoPoint,
    aggregate_commit: &RistrettoPoint,
) -> SignaturePart {
    // Challenge c = H(R || A || m)
    let mut hasher = Sha512::new();
    hasher.update(aggregate_commit.compress().as_bytes());
    hasher.update(aggregate_pk.compress().as_bytes());
    hasher.update(message);

    let hash_result = hasher.finalize(); // 64 bytes
    let c = Scalar::from_bytes_mod_order_wide(&hash_result[..64].try_into().unwrap());

    // s = r + c * sk
    let s = secret_r + c * sk;

    SignaturePart { s }
}

fn cosi_commit(seed: &str) -> (Commitment, Secret) {
    // Step 1: SHA512(seed)
    let mut hasher = Sha512::new();
    hasher.update(seed.as_bytes());
    let hash = hasher.finalize();
    // Step 2: Use hash as deterministic RNG seed
    let mut rng = ChaChaRng::from_seed(hash[0..32].try_into().unwrap());

    // Step 3: Generate scalar r
    let mut r_bytes = [0u8; 64];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

    // Step 4: Compute R = g^r
    let R = &r * &RISTRETTO_BASEPOINT_POINT;

    (
        Commitment { R },
        Secret { r },
    )
}

pub fn generate_keys() -> (RistrettoPoint, Scalar) {
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 64];
    rng.fill_bytes(&mut sk_bytes); // ✅ now works
    let sk = Scalar::from_bytes_mod_order_wide(&sk_bytes);
    let pk = &sk * &RISTRETTO_BASEPOINT_POINT;
    (pk, sk)
}

pub fn sign_aggregate_example(
    message: &str,
    pub_keys: &[RistrettoPoint ],
    pri_key1: Scalar,
    pri_key2: Scalar,
    pri_key3: Scalar,
) -> Vec<u8> {
    let (commit1, secret1) = cosi_commit(message);
    let (commit2, secret2) = cosi_commit(message);
    let (commit3, secret3) = cosi_commit(message);
    let commits = vec![commit1, commit2, commit3];

    let cosigners = Cosigners::new(pub_keys.to_vec());
    let agg_pk = cosigners.aggregate_public_key();
    let agg_commit = cosigners.aggregate_commit(&commits);

    let sig1 = cosign(&pri_key1, &secret1.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig2 = cosign(&pri_key2, &secret2.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig3 = cosign(&pri_key3, &secret3.r, message.as_bytes(), &agg_pk, &agg_commit);

    let sig_parts = vec![sig1, sig2, sig3];

    cosigners.aggregate_signature(agg_commit, &sig_parts)
}

pub fn verify_aggregate_signature(
    pub_keys: &[RistrettoPoint],
    message:   &[u8],
    sig:       &[u8],            // 직렬화된 집단서명
) -> bool {
    /* ---------- 1. 길이·형식 검사 ---------- */
    let mask_len = (pub_keys.len() + 7) / 8;
    if sig.len() != 64 + mask_len {
        return false;
    }
    let (r_bytes, rest) = sig.split_at(32);
    let (s_bytes, mask) = rest.split_at(32);

    /* ---------- 2. R 복원 ---------- */
    let r_comp = match CompressedRistretto::from_slice(r_bytes) {
        Ok(c)  => c,
        Err(_) => return false,
    };
    let r_point = match r_comp.decompress() {
        Some(p) => p,
        None    => return false,
    };

    /* ---------- 3. S 복원 & 정칙성 ---------- */
    let s_ct: CtOption<Scalar> =
        Scalar::from_canonical_bytes(s_bytes.try_into().unwrap());
    if s_ct.is_some().unwrap_u8() == 0 {
        return false;                             // 비정칙 스칼라
    }
    let s_scalar = s_ct.unwrap();

    /* ---------- 4. 집계 공개키 A = Σ P_i (mask 적용) ---------- */
    let agg_pk = pub_keys.iter().enumerate().fold(
        RistrettoPoint::default(),
        |acc, (i, pk)| {
            let bit = (mask[i / 8] >> (i % 8)) & 1;
            if bit == 1 { acc + pk } else { acc }
        },
    );

    /* ---------- 5. 챌린지 c = H(R ‖ A ‖ m) ---------- */
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(agg_pk.compress().as_bytes());
    h.update(message);
    let digest = h.finalize();
    let c = Scalar::from_bytes_mod_order_wide(&digest[..64].try_into().unwrap());

    /* ---------- 6. Schnorr 검증 ---------- */
    let lhs = &s_scalar * &RISTRETTO_BASEPOINT_POINT; // s·B
    let rhs = r_point + c * agg_pk;                    // R + c·A
    lhs == rhs
}