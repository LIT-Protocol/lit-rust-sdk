use sha2::{Digest, Sha256};

#[tokio::test]
async fn test_hash_combinations() {
    // Expected hash from the lit-node logs
    let expected_hash = "53b01f820c82e86d7e4cd804b8a6f68682221eeb7df76fd43ee777c8caab5628";

    println!("🎯 Target hash: {}", expected_hash);

    // Try various JSON format combinations
    let test_cases = [
        // Basic format (what we currently have)
        r#"[{"contractAddress":"","standardContractType":"","chain":"ethereum","method":"eth_getBalance","parameters":[":userAddress","latest"],"returnValueTest":{"comparator":">=","value":"0"}}]"#,
        // Field order variation 1
        r#"[{"contractAddress":"","chain":"ethereum","standardContractType":"","method":"eth_getBalance","parameters":[":userAddress","latest"],"returnValueTest":{"comparator":">=","value":"0"}}]"#,
        // Field order variation 2
        r#"[{"chain":"ethereum","contractAddress":"","standardContractType":"","method":"eth_getBalance","parameters":[":userAddress","latest"],"returnValueTest":{"comparator":">=","value":"0"}}]"#,
        // With localchain instead of ethereum
        r#"[{"contractAddress":"","standardContractType":"","chain":"localchain","method":"eth_getBalance","parameters":[":userAddress","latest"],"returnValueTest":{"comparator":">=","value":"0"}}]"#,
        // With different value format (numeric 0)
        r#"[{"contractAddress":"","standardContractType":"","chain":"ethereum","method":"eth_getBalance","parameters":[":userAddress","latest"],"returnValueTest":{"comparator":">=","value":0}}]"#,
        // Try unified format exactly as the lit-node working test expects
        r#"[{"Condition":{"contractAddress":"","chain":"ethereum","standardContractType":"","method":"eth_getBalance","parameters":[":userAddress","latest"],"returnValueTest":{"comparator":">=","value":"0"}}}]"#,
    ];

    for (i, json_str) in test_cases.iter().enumerate() {
        let mut hasher = Sha256::new();
        hasher.update(json_str.as_bytes());
        let hash = hex::encode(hasher.finalize());

        println!("Test case {}: {}", i + 1, json_str);
        println!("  Hash: {}", hash);

        if hash == expected_hash {
            println!("  🎉 MATCH FOUND!");
        }
        println!();
    }
}
