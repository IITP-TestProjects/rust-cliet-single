use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use ecvrf::{prove, verify, VrfPk, VrfSk, VrfProof};
use subtle::CtOption;
use rand::rngs::OsRng;
use sha2::{Sha512, Sha256, Digest};
use rand_chacha::ChaChaRng;
use rand_core::{SeedableRng, RngCore};
use zeroize::Zeroize;

pub struct Commitment {
    pub R: RistrettoPoint,
}

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Secret (Scalar);

pub struct Cosigners {
    pub_keys: Vec<RistrettoPoint>,
}

pub struct SignaturePart {
    pub s: Scalar,
}

impl Secret {
    pub fn new(s: Scalar) -> Self { Secret(s)}
    fn into_inner(self) -> Scalar {
        let Secret(s) = self;
        s
    }
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
        //마스크 생성 안함.
        /* let mut mask = vec![0u8; (self.pub_keys.len() + 7) / 8];
        for i in 0..self.pub_keys.len() {
            mask[i / 8] |= 1 << (i % 8);
        } */

        // 3. 직렬화: 32B R + 32B S + mask
        let mut sig = Vec::with_capacity(64 /* + mask.len() */);
        sig.extend_from_slice(agg_commit.compress().as_bytes()); // R
        sig.extend_from_slice(&agg_s.to_bytes());                // S
        //sig.extend_from_slice(&mask);                          // mask 생성안함
        sig
    }
}

pub fn cosign(
    sk: &Scalar,
    secret: Secret,
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

    //s = r + c * sk
    let secret_r = secret.into_inner(); // 비밀 스칼라 r
    let s = secret_r + c * sk;

    SignaturePart { s }
}

pub fn cosi_commit(seed: &str) -> (Commitment, Secret) {
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
        Secret::new(r),
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

pub fn verify_aggregate_signature(
    pub_keys: &[RistrettoPoint],
    message:   &[u8],
    sig:       &[u8],            // 직렬화된 집단서명
) -> bool {
    /* ---------- 1. 길이·형식 검사 ---------- */
    //let mask_len = (pub_keys.len() + 7) / 8;
    if sig.len() != 64 /* + mask_len */ { return false; }
    let (r_bytes, s_bytes /* rest */) = sig.split_at(32);
    //let (s_bytes, mask) = rest.split_at(32);

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
    if s_ct.is_some().unwrap_u8() == 0 { return false; }
    let s_scalar = s_ct.unwrap();

    /* ---------- 4. 집계 공개키 A = Σ P_i (mask 적용) ---------- */
    let agg_pk = pub_keys.iter()/* .enumerate() */.fold(
        RistrettoPoint::default(),
        |acc, pk| acc + pk);
            /* let bit = (mask[i / 8] >> (i % 8)) & 1;
            if bit == 1 { acc + pk } else { acc }
        },
    ); */

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

// 0‥1 실수값으로 변환 (상위 8 바이트만 사용)
fn hash_ratio(vrf_output: &[u8]) -> f64 {
    let h = Sha256::digest(vrf_output);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h[..8]);
    (u64::from_be_bytes(b) as f64) / (u64::MAX as f64)
}

/// N-of-N 환경: threshold=1.0 → 모든 노드 선출
pub fn generate_vrf_output(
    seed:      &str,
    pub_key:   &RistrettoPoint,   // ← 공개키(RistrettoPoint)
    sec_key:   &Scalar,           // ← 비밀스칼라
    threshold: f64,
) -> Option<Vec<u8>> {
    /* 1. 메시지 = SHA-256(seed) */
    let msg = Sha256::digest(seed.as_bytes());

    /* 2. RistrettoPoint‧Scalar → ecvrf 키 구조체 */
    let sk_bytes = sec_key.to_bytes();
    let vrf_sk   = VrfSk::from_bytes(&sk_bytes).expect("bad scalar");

    let pk_bytes = pub_key.compress().to_bytes();       // 32B
    let vrf_pk   = VrfPk::from_bytes(&pk_bytes).expect("bad point");

    /* 3. prove → (hash, proof) */
    let (vrf_hash, proof): ([u8; 32], VrfProof) =
        prove(&msg, &vrf_sk);

    /* 4. verify */
    if !verify(&msg, &vrf_pk, &vrf_hash, &proof) {
        return None;                                    // 검증 실패
    }

    /* 5. ratio & sortition */
    let ratio = hash_ratio(&vrf_hash);
    let selected = ratio < threshold;
    println!("EXECUTING_VRF_RATIO_RESULT: {ratio}  selected={selected}");

    if selected {
        Some(proof.to_bytes().to_vec())                 // π 반환
    } else {
        None
    }
}