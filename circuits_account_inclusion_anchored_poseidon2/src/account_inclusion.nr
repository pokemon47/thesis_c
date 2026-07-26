pub fn statement_tag() -> Field {
    1
}

pub fn prove(
    state_root: [u8; 32],
    state_root_field: Field,
    account_address: [u8; 20],
    hash_variant_id: Field,
    witness_version: Field,
    trie_key: [u8; 32],
    active_node_count: Field,
    node_bytes: [[u8; 1024]; 16],
    node_lengths: [Field; 16],
    node_kinds: [Field; 16],
    node_list_layouts: [[Field; 4]; 16],
    node_item_layouts: [[[Field; 4]; 17]; 16],
    node_compact_layouts: [[Field; 4]; 16],
    selected_ref_layouts: [[Field; 4]; 16],
    selected_ref_bytes: [[u8; 32]; 16],
    selected_ref_lengths: [Field; 16],
    selected_ref_kinds: [Field; 16],
    terminal_value: [u8; 256],
    terminal_value_len: Field,
) {
    assert(hash_variant_id == 2);
    assert(
        crate::expanded_hash_poseidon2::bytes32_to_field(state_root)
            == state_root_field
    );
    assert(
        crate::hash_poseidon2::hash_address_field(account_address)
            == crate::expanded_hash_poseidon2::bytes32_to_field(trie_key)
    );

    let authenticated_terminal = crate::mpt_inclusion::assert_inclusion(
        witness_version,
        state_root,
        state_root_field,
        trie_key,
        active_node_count,
        node_bytes,
        node_lengths,
        node_kinds,
        node_list_layouts,
        node_item_layouts,
        node_compact_layouts,
        selected_ref_layouts,
        selected_ref_bytes,
        selected_ref_lengths,
        selected_ref_kinds,
        terminal_value,
        terminal_value_len,
    );

    crate::account_terminal::assert_canonical_terminal_account_rlp(
        authenticated_terminal.value_bytes,
        authenticated_terminal.value_len,
    );
}
