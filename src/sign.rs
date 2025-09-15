use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use subtle::CtOption;
use rand::rngs::OsRng;
use sha2::{Sha512, Sha256, Digest};
use rand_chacha::ChaChaRng;
use rand_core::{SeedableRng, RngCore};
use zeroize::Zeroize;

pub struct Commitment { pub R: EdwardsPoint }

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Secret (Scalar);

pub struct Cosigners { pub_keys: Vec<EdwardsPoint> }

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
    pub fn new(pub_keys: Vec<EdwardsPoint>) -> Self {
        Self { pub_keys }
    }

    pub fn aggregate_public_key(&self) -> EdwardsPoint {
        self.pub_keys.iter().fold(EdwardsPoint::identity(), |acc, pk| acc + pk)
    }

    pub fn aggregate_commit(&self, commits: &[Commitment]) -> EdwardsPoint {
        commits.iter().fold(EdwardsPoint::identity(), |acc, c| acc + c.R)
    }

    pub fn aggregate_signature(
        &self,
        agg_commit: EdwardsPoint,          // R
        sig_parts: &[SignaturePart],       // s_i 집합
    ) -> Vec<u8> {                         // (R‖S) — 레거시: 마스크 미포함
        // 1. S = Σ s_i
        let agg_s = sig_parts
            .iter()
            .fold(Scalar::default(), |acc, p| acc + p.s);

        // 2. 직렬화: 32B R + 32B S
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(agg_commit.compress().as_bytes()); // R
        sig.extend_from_slice(&agg_s.to_bytes());                // S
        sig
    }

    /// 마스크를 별도 변수로 반환하는 집계 함수
    /// 반환값: (signature_bytes: 64바이트 R||S, mask_bytes: ceil(N/8) 바이트)
    pub fn aggregate_signature_split(
        &self,
        agg_commit: EdwardsPoint,
        sig_parts: &[SignaturePart],
    ) -> (Vec<u8>, Vec<u8>) {
        // 1) S = Σ s_i
        let agg_s = sig_parts
            .iter()
            .fold(Scalar::default(), |acc, p| acc + p.s);

        // 2) R||S
        let mut sig = Vec::with_capacity(64);
        sig.extend_from_slice(agg_commit.compress().as_bytes());
        sig.extend_from_slice(&agg_s.to_bytes());

        // 3) mask: 활성(참여) = 1, 비활성 = 0
        //    현재 구현은 전원 참여 가정 (필요 시 참여 인덱스에 따라 비트 세팅 로직 적용)
        let mut mask = vec![0u8; (self.pub_keys.len() + 7) / 8];
        for i in 0..self.pub_keys.len() {
            mask[i / 8] |= 1 << (i % 8);
        }

        (sig, mask)
    }
}

/// 정렬 기반 로스터 해시 계산
/// rosterHash = SHA-256(concat(sorted(compressed_pubkeys)))
pub fn compute_roster_hash(pub_keys: &[EdwardsPoint]) -> [u8; 32] {
    // 1) 각 공개키를 32바이트 압축 형태로 수집
    let mut bytes_vec: Vec<[u8; 32]> = pub_keys
        .iter()
        .map(|pk| pk.compress().to_bytes())
        .collect();
    // 2) 사전식 정렬로 순서 독립 집합 커밋
    bytes_vec.sort_unstable();
    // 3) 이어붙여 SHA-256
    let mut h = Sha256::new();
    for b in &bytes_vec {
        h.update(b);
    }
    let out = h.finalize();
    let mut rh = [0u8; 32];
    rh.copy_from_slice(&out[..32]);
    rh
}

pub fn cosign(
    sk_seed: &[u8; 32],
    secret: Secret,
    message: &[u8],
    aggregate_pk: &EdwardsPoint,
    aggregate_commit: &EdwardsPoint,
) -> SignaturePart {
    // expanded+clamped secret scalar from seed
    let mut h0 = Sha512::new();
    h0.update(sk_seed);
    let d = h0.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d[..32]);
    k[0] &= 248; k[31] &= 63; k[31] |= 64;
    let k_scalar = Scalar::from_bytes_mod_order(k);

    // Challenge c = H(R || A || m)
    let mut hasher = Sha512::new();
    hasher.update(aggregate_commit.compress().as_bytes());
    hasher.update(aggregate_pk.compress().as_bytes());
    hasher.update(message);
    let hash_result = hasher.finalize();
    let c = Scalar::from_bytes_mod_order_wide(&hash_result[..64].try_into().unwrap());

    let secret_r = secret.into_inner();
    let s = secret_r + c * k_scalar;
    SignaturePart { s }
}

/// 로스터 해시를 챌린지에 바인딩하여 서명하는 변형
/// c = H(R || A || m || rosterHash)
pub fn cosign_with_roster_hash(
    sk_seed: &[u8; 32],
    secret: Secret,
    message: &[u8],
    aggregate_pk: &EdwardsPoint,
    aggregate_commit: &EdwardsPoint,
    roster_hash: &[u8; 32],
) -> SignaturePart {
    // expanded+clamped secret scalar from seed
    let mut h0 = Sha512::new();
    h0.update(sk_seed);
    let d = h0.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d[..32]);
    k[0] &= 248; k[31] &= 63; k[31] |= 64;
    let k_scalar = Scalar::from_bytes_mod_order(k);

    let mut hasher = Sha512::new();
    hasher.update(aggregate_commit.compress().as_bytes());
    hasher.update(aggregate_pk.compress().as_bytes());
    hasher.update(message);
    hasher.update(roster_hash);
    let hash_result = hasher.finalize();
    let c = Scalar::from_bytes_mod_order_wide(&hash_result[..64].try_into().unwrap());

    let secret_r = secret.into_inner();
    let s = secret_r + c * k_scalar;
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
    let R = &r * &ED25519_BASEPOINT_POINT;

    (
        Commitment { R },
        Secret::new(r),
    )
}

pub fn generate_keys() -> (EdwardsPoint, [u8; 32]) {
    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let mut h = Sha512::new();
    h.update(&seed);
    let d = h.finalize();
    let mut k = [0u8; 32];
    k.copy_from_slice(&d[..32]);
    k[0] &= 248; k[31] &= 63; k[31] |= 64;
    let k_scalar = Scalar::from_bytes_mod_order(k);
    let pk = &k_scalar * &ED25519_BASEPOINT_POINT;
    (pk, seed)
}

pub fn verify_aggregate_signature(
    pub_keys: &[EdwardsPoint],
    message:   &[u8],
    sig:       &[u8],            // 직렬화된 집단서명 (R||S) — 레거시: 마스크 미포함
) -> bool {
    /* ---------- 1. 길이·형식 검사 ---------- */
    if sig.len() != 64 { return false; }
    let (r_bytes, s_bytes /* rest */) = sig.split_at(32);

    /* ---------- 2. R 복원 ---------- */
    let r_comp = match CompressedEdwardsY::from_slice(r_bytes) {
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

    /* ---------- 4. 집계 공개키 A = Σ P_i (전원 참여 가정) ---------- */
    let agg_pk = pub_keys
        .iter()
        .fold(EdwardsPoint::identity(), |acc, pk| acc + pk);

    /* ---------- 5. 챌린지 c = H(R ‖ A ‖ m) ---------- */
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(agg_pk.compress().as_bytes());
    h.update(message);
    let digest = h.finalize();
    let c = Scalar::from_bytes_mod_order_wide(&digest[..64].try_into().unwrap());

    /* ---------- 6. Schnorr 검증 ---------- */
    let lhs = &s_scalar * &ED25519_BASEPOINT_POINT; // s·B
    let rhs = r_point + c * agg_pk;                    // R + c·A
    lhs == rhs
}

/// 로스터 해시를 챌린지에 바인딩하여 검증
/// 서명 시에도 동일하게 c = H(R || A || m || rosterHash)로 생성되어야 함
pub fn verify_aggregate_signature_with_roster(
    pub_keys: &[EdwardsPoint],
    message:   &[u8],
    sig:       &[u8],
) -> bool {
    // 1) 길이 검사 및 R,S 복원
    if sig.len() != 64 { return false; }
    let (r_bytes, s_bytes) = sig.split_at(32);

    let r_comp = match CompressedEdwardsY::from_slice(r_bytes) {
        Ok(c)  => c,
        Err(_) => return false,
    };
    let r_point = match r_comp.decompress() { Some(p) => p, None => return false };

    let s_ct: CtOption<Scalar> = Scalar::from_canonical_bytes(s_bytes.try_into().unwrap());
    if s_ct.is_some().unwrap_u8() == 0 { return false; }
    let s_scalar = s_ct.unwrap();

    // 2) 집계 공개키 A = Σ P_i
    let agg_pk = pub_keys
        .iter()
        .fold(EdwardsPoint::identity(), |acc, pk| acc + pk);

    // 3) 로스터 해시 계산(정렬 기반)
    let roster_hash = compute_roster_hash(pub_keys);

    // 4) 챌린지 c = H(R || A || m || rosterHash)
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(agg_pk.compress().as_bytes());
    h.update(message);
    h.update(&roster_hash);
    let digest = h.finalize();
    let c = Scalar::from_bytes_mod_order_wide(&digest[..64].try_into().unwrap());

    // 5) Schnorr 등식 검사
    let lhs = &s_scalar * &ED25519_BASEPOINT_POINT;
    let rhs = r_point + c * agg_pk;
    lhs == rhs
}
/// 마스크를 별도 인자로 받아 검증하는 함수
/// - sig: 64바이트(R||S)
/// - mask: ceil(N/8) 바이트, 비트 1 = 참여, 0 = 비참여
pub fn verify_aggregate_signature_with_mask(
    pub_keys: &[EdwardsPoint],
    message:   &[u8],
    sig:       &[u8],
    mask:      &[u8],
) -> bool {
    // 1) 길이 검사
    if sig.len() != 64 { return false; }
    let expected_mask_len = (pub_keys.len() + 7) / 8;
    if mask.len() != expected_mask_len { return false; }

    let (r_bytes, s_bytes) = sig.split_at(32);

    // 2) R 복원
    let r_comp = match CompressedEdwardsY::from_slice(r_bytes) {
        Ok(c)  => c,
        Err(_) => return false,
    };
    let r_point = match r_comp.decompress() {
        Some(p) => p,
        None    => return false,
    };

    // 3) S 복원
    let s_ct: CtOption<Scalar> = Scalar::from_canonical_bytes(s_bytes.try_into().unwrap());
    if s_ct.is_some().unwrap_u8() == 0 { return false; }
    let s_scalar = s_ct.unwrap();

    // 4) mask 적용한 집계 공개키 A
    let mut agg_pk = EdwardsPoint::identity();
    for (i, pk) in pub_keys.iter().enumerate() {
        let bit = (mask[i / 8] >> (i % 8)) & 1;
        if bit == 1 { agg_pk = agg_pk + pk; }
    }

    // 5) 챌린지 c = H(R||A||m)
    let mut h = Sha512::new();
    h.update(r_bytes);
    h.update(agg_pk.compress().as_bytes());
    h.update(message);
    let digest = h.finalize();
    let c = Scalar::from_bytes_mod_order_wide(&digest[..64].try_into().unwrap());

    // 6) Schnorr 검증
    let lhs = &s_scalar * &ED25519_BASEPOINT_POINT; // s·B
    let rhs = r_point + c * agg_pk;                    // R + c·A(masked)
    lhs == rhs
}

// VRF 관련 예제 코드는 Ed25519 호환 작업 범위를 넘어가므로 제거했습니다.
