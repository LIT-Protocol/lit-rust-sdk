use crate::types::ConnectionState;
use std::collections::HashMap;

impl super::LitNodeClient {
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn connected_nodes(&self) -> Vec<String> {
        self.connection_state
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    pub fn get_connection_state(&self) -> ConnectionState {
        let mut server_keys = HashMap::new();
        let connected_nodes: Vec<String> = self
            .connection_state
            .iter()
            .map(|entry| {
                server_keys.insert(entry.key().clone(), entry.handshake_response.clone());
                entry.key().clone()
            })
            .collect();

        ConnectionState {
            connected_nodes,
            server_keys,
            subnet_pub_key: self.subnet_pub_key.clone(),
            network_pub_key: self.network_pub_key.clone(),
            network_pub_key_set: self.network_pub_key_set.clone(),
            hd_root_pubkeys: self.hd_root_pubkeys.clone(),
            latest_blockhash: self.latest_blockhash.clone(),
        }
    }
}
