mod sign;

fn main() {
    //각 노드별 서명 생성 
    let (pub_key1, pri_key1) = sign::generate_keys();
    let (pub_key2, pri_key2) = sign::generate_keys();
    let (pub_key3, pri_key3) = sign::generate_keys();

    let pub_keys = vec![pub_key1, pub_key2, pub_key3];

    let message = "Seed";
    let agg_sign = sign::sign_aggregate_example(message, &pub_keys, pri_key1, pri_key2, pri_key3);

    let valid = sign::verify_aggregate_signature(&pub_keys, message.as_bytes(), &agg_sign);
    println!("Valid? {}", valid);
}