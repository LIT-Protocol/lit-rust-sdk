use lit_rust_sdk::accs::hash_unified_access_control_conditions;
use serde_json::json;

#[test]
fn hash_unified_evm_basic_is_stable() {
    let unified = json!([
        {
            "conditionType": "evmBasic",
            "contractAddress": "",
            "standardContractType": "",
            "chain": "ethereum",
            "method": "eth_getBalance",
            "parameters": [":userAddress", "latest"],
            "returnValueTest": {
                "comparator": ">=",
                "value": "1000000000000000000"
            }
        }
    ]);

    let hash = hash_unified_access_control_conditions(&unified).unwrap();
    assert_eq!(
        hex::encode(hash),
        "fe03dae8cc43dc1f64cdad9d147fb6e527ccc0d33d1be86b79a9fb41d3ea842c"
    );
}
