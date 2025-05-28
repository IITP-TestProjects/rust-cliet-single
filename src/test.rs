fn sign_aggregate_example(
    message: &str,
    pub_keys: &[RistrettoPoint ],
    pri_key1: Scalar, pri_key2: Scalar,
    pri_key3: Scalar, pri_key4: Scalar,
    pri_key5: Scalar, pri_key6: Scalar,
    pri_key7: Scalar, pri_key8: Scalar,
    pri_key9: Scalar, pri_key10: Scalar,
) -> Vec<u8> {
    // 1. 서명에 필요한 커밋데이터 생성 secret 데이터는 공유금지.
    // 각 노드에서 message로 생성한 커밋데이터를 metric data와 함께 CEF로 전달 필요
    let (commit1, secret1) = cosi_commit(message);
    let (commit2, secret2) = cosi_commit(message);
    let (commit3, secret3) = cosi_commit(message);
    let (commit4, secret4) = cosi_commit(message);
    let (commit5, secret5) = cosi_commit(message);
    let (commit6, secret6) = cosi_commit(message);
    let (commit7, secret7) = cosi_commit(message);
    let (commit8, secret8) = cosi_commit(message);
    let (commit9, secret9) = cosi_commit(message);
    let (commit10, secret10) = cosi_commit(message);

    //이후, 각 노드에서 ReauestCommittee RPC에 round, nodeId, seed, 

    // 2. CEF에서 commit과 public key를 모두 모아 처리하는 과정:
    // 압축public key 및 압축 commit 생성 및 커미티 정보와 함께 각 노드에 전달
    let commits = vec![commit1, commit2, commit3, commit4, 
        commit5, commit6, commit7, commit8, commit9, commit10];
    let cosigners = Cosigners::new(pub_keys.to_vec());
    let agg_pk = cosigners.aggregate_public_key();
    let agg_commit = cosigners.aggregate_commit(&commits);

    // 3. 각 노드에서 2.에서 전달받은 데이터를 이용해 특정 라운드의 
    // 동일한 messasge에 대해 서명 생성 및 primary node로 전달
    let sig1 = cosign(&pri_key1, &secret1.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig2 = cosign(&pri_key2, &secret2.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig3 = cosign(&pri_key3, &secret3.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig4: SignaturePart = cosign(&pri_key4, &secret4.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig5: SignaturePart = cosign(&pri_key5, &secret5.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig6: SignaturePart = cosign(&pri_key6, &secret6.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig7: SignaturePart = cosign(&pri_key7, &secret7.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig8: SignaturePart = cosign(&pri_key8, &secret8.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig9: SignaturePart = cosign(&pri_key9, &secret9.r, message.as_bytes(), &agg_pk, &agg_commit);
    let sig10: SignaturePart = cosign(&pri_key10, &secret10.r, message.as_bytes(), &agg_pk, &agg_commit);

    // 4. Primary node에서 서명 집계
    let sig_parts = vec![sig1, sig2, sig3, sig4, sig5, 
        sig6, sig7, sig8, sig9, sig10];

    // 5. Primary node에서 서명 압축
    let agg_sig = cosigners.aggregate_signature(agg_commit, &sig_parts);

    //sign별 크기출력:
    println!("• SignaturePart 타입 크기(정적): {} bytes", size_of::<SignaturePart>());
    for (i, sp) in sig_parts.iter().enumerate() {
        // SignaturePart 자체는 메모리에 Scalar 하나(32바이트)만 보유
        println!("  ├─ sig{} 크기: {} bytes", i + 1, size_of::<SignaturePart>());
        println!("      값 32바이트? {:?}", sp.s.to_bytes().len());
    }

    println!("• 집계 서명 agg_sig 길이: {} bytes", agg_sig.len());
    return agg_sig;
}