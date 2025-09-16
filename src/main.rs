mod sign;
use std::{thread, time::Duration};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Sha512, Digest};

fn main() {
    // client 1: 각 노드별 공개키-비밀키 쌍 생성(10개 노드)
    let (pub_key1, priv_key1) = sign::generate_keys();
    let (pub_key2, priv_key2) = sign::generate_keys();
    let (pub_key3, priv_key3) = sign::generate_keys();
    let (pub_key4, priv_key4) = sign::generate_keys();
    let (pub_key5, priv_key5) = sign::generate_keys();
    let (pub_key6, priv_key6) = sign::generate_keys();
    let (pub_key7, priv_key7) = sign::generate_keys();
    let (pub_key8, priv_key8) = sign::generate_keys();
    let (pub_key9, priv_key9) = sign::generate_keys();
    let (pub_key10, priv_key10) = sign::generate_keys();

    let seeds = vec![
        "seed-node1",
        "seed-node2",
        "seed-node3",
        "seed-node4",
        "seed-node5",
        "seed-node6",
        "seed-node7",
        "seed-node8",
        "seed-node9",
        "seed-node10",
    ];

    // client 2: 각 노드별 VRF 출력 생성(데모). Ed25519 seed에서 VRF 키를 유도해 사용
    let _vrf_proof1  = sign::generate_vrf_output_from_ed25519(seeds[0], &pub_key1,  &priv_key1,  1.0);
    let _vrf_proof2  = sign::generate_vrf_output_from_ed25519(seeds[1], &pub_key2,  &priv_key2,  1.0);
    let _vrf_proof3  = sign::generate_vrf_output_from_ed25519(seeds[2], &pub_key3,  &priv_key3,  1.0);
    let _vrf_proof4  = sign::generate_vrf_output_from_ed25519(seeds[3], &pub_key4,  &priv_key4,  1.0);
    let _vrf_proof5  = sign::generate_vrf_output_from_ed25519(seeds[4], &pub_key5,  &priv_key5,  1.0);
    let _vrf_proof6  = sign::generate_vrf_output_from_ed25519(seeds[5], &pub_key6,  &priv_key6,  1.0);
    let _vrf_proof7  = sign::generate_vrf_output_from_ed25519(seeds[6], &pub_key7,  &priv_key7,  1.0);
    let _vrf_proof8  = sign::generate_vrf_output_from_ed25519(seeds[7], &pub_key8,  &priv_key8,  1.0);
    let _vrf_proof9  = sign::generate_vrf_output_from_ed25519(seeds[8], &pub_key9,  &priv_key9,  1.0);
    let _vrf_proof10 = sign::generate_vrf_output_from_ed25519(seeds[9], &pub_key10, &priv_key10, 1.0);

    println!("--- CoSi Signature with Roster Hash Example --- {:?}", _vrf_proof1);

    loop {
        // client 3: 각 노드별 commit 생성
        let (commit1, secretR1) = sign::cosi_commit(seeds[0]);
        let (commit2, secretR2) = sign::cosi_commit(seeds[1]);
        let (commit3, secretR3) = sign::cosi_commit(seeds[2]);
        let (commit4, secretR4) = sign::cosi_commit(seeds[3]);
        let (commit5, secretR5) = sign::cosi_commit(seeds[4]);
        let (commit6, secretR6) = sign::cosi_commit(seeds[5]);
        let (commit7, secretR7) = sign::cosi_commit(seeds[6]);
        let (commit8, secretR8) = sign::cosi_commit(seeds[7]);
        let (commit9, secretR9) = sign::cosi_commit(seeds[8]);
        let (commit10, secretR10) = sign::cosi_commit(seeds[9]);

        //이후, 각 노드에서 round, nodeId, seed, vrfProof, publicKey, commit 및 metric data를 server로 전달
        //=================================server side=================================
        // server 1. RequestCommittee RPC에서 수신한 정보들을 수집하고 처리 시작
        // server 2. metric data, vrfOutput, publicKey를 verify 노드에 보내서 커미티 선정 정보 수신
        // vrf output, publickey, seed를 활용해 실제 해당 노드가 threshold를 만족하는지 검증가능하므로
        // server 3. 수신한 커미티에 대해서 압축 public key 및 압축 commit 생성

        // 커미티가 생성된 이후에는 pub_keys 집계는 필요없음. -> 별개의 RPC를 통해 commitment만 압축해서 전달
        let pub_keys = vec![
            pub_key1, pub_key2, pub_key3, pub_key4, pub_key5, pub_key6, pub_key7, pub_key8,
            pub_key9, pub_key10,
        ];
        let commits = vec![
            commit1, commit2, commit3, commit4, commit5, commit6, commit7, commit8, commit9,
            commit10,
        ];

        // 현재는 서버와 같은 코드 내이지만, 실제로는 전달된 데이터를 통해 client측에서도 cosigners를 생성해야 함.
        let cosigners = sign::Cosigners::new(pub_keys.to_vec());
        let agg_pk = cosigners.aggregate_public_key();
        let agg_commit = cosigners.aggregate_commit(&commits);
        // 정렬 기반 로스터 해시 계산
        let roster_hash = sign::compute_roster_hash(&pub_keys);
        // server 4. 생성한 agg_pk, agg_commit을 각 노드에 전달(JoinNetwork로 boradcast)
        // 반환하는 데이터: round, nodeIds(committees), agg_pk, agg_commit, publicKeys, rosterHash
        //=================================server side end=================================

        // client 4: 커미티가 된 각 노드에서 특정 라운드의 동일한 메시지에 대해 각자의 priv_key로 서명을 생성

        let message = "Hello, world!";
        let sig1 = sign::cosign_with_roster_hash(
            &priv_key1,
            secretR1,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig2 = sign::cosign_with_roster_hash(
            &priv_key2,
            secretR2,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig3 = sign::cosign_with_roster_hash(
            &priv_key3,
            secretR3,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig4 = sign::cosign_with_roster_hash(
            &priv_key4,
            secretR4,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig5 = sign::cosign_with_roster_hash(
            &priv_key5,
            secretR5,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig6 = sign::cosign_with_roster_hash(
            &priv_key6,
            secretR6,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig7 = sign::cosign_with_roster_hash(
            &priv_key7,
            secretR7,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig8 = sign::cosign_with_roster_hash(
            &priv_key8,
            secretR8,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig9 = sign::cosign_with_roster_hash(
            &priv_key9,
            secretR9,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );
        let sig10 = sign::cosign_with_roster_hash(
            &priv_key10,
            secretR10,
            message.as_bytes(),
            &agg_pk,
            &agg_commit,
            &roster_hash,
        );

        // client 5: 각 노드에서 생성한 서명을 primary node로 전달해 primary node에서 서명 압축
        let sig_parts = vec![sig1, sig2, sig3, sig4, sig5, sig6, sig7, sig8, sig9, sig10];
        // 새로운 API: 서명(R||S)와 mask를 분리해 반환
        let (agg_sig, _mask) = cosigners.aggregate_signature_split(agg_commit, &sig_parts);

        // 로스터 바인딩 검증(정렬 해시 내장)
        let valid = sign::verify_aggregate_signature_with_roster(&pub_keys, message.as_bytes(), &agg_sig);
        println!("Valid(with rosterHash)? {}", valid);

        println!("agg_sig: {} bytes", agg_sig.len());

        // ----- 추가 데모: Schnorr 등식 S*B == R + c*A 직접 확인 -----
        let (r_bytes, s_bytes) = agg_sig.split_at(32);
        let r_comp = CompressedEdwardsY::from_slice(r_bytes).expect("bad R bytes");
        let r_point = r_comp.decompress().expect("R decompress failed");
        let s_scalar = Scalar::from_canonical_bytes(s_bytes.try_into().unwrap())
            .unwrap();

        // A = P_i 합산
        let agg_pk_check: EdwardsPoint = pub_keys.iter().fold(EdwardsPoint::identity(), |acc, pk| acc + pk);

        // c = H(R || A || m || rosterHash)
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(agg_pk_check.compress().as_bytes());
        h.update(message.as_bytes());
        h.update(&roster_hash);
        let digest = h.finalize();
        let c = Scalar::from_bytes_mod_order_wide(&digest[..64].try_into().unwrap());

        let lhs = &s_scalar * &ED25519_BASEPOINT_POINT;     // S·B
        let rhs = r_point + c * agg_pk_check;               // R + c·A
        println!("Equation holds? {}", lhs == rhs);

        thread::sleep(Duration::from_secs(5));
    }
}
