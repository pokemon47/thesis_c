global MAX_ACCOUNT_PROOF_NODES: u32 = 4;
global MAX_ACCOUNT_NODE_BYTES: u32 = 544;
global ACCOUNT_PATH_NIBBLES: u32 = 64;
global MAX_LEAF_PATH_NIBBLES: u32 = 64;
global MAX_BRANCH_NODES: u32 = 3;
global BRANCH_CHILD_SLOTS: u32 = 16;

pub fn assert_nibble(value: Field) {
    assert((value as u32) < BRANCH_CHILD_SLOTS);
}

pub fn bytes32_to_field(input: [u8; 32]) -> Field {
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + input[i] as Field;
    }
    acc
}

pub fn bytes20_to_field(input: [u8; 20]) -> Field {
    let mut acc: Field = 0;
    for i in 0..20 {
        acc = acc * 256 + input[i] as Field;
    }
    acc
}

pub fn compute_leaf_fields_commitment(
    nonce: Field,
    balance: Field,
    storage_root: [u8; 32],
    code_hash: [u8; 32],
) -> Field {
    let mut acc = nonce + balance * 17;
    for i in 0..32 {
        acc = acc * 257 + storage_root[i] as Field;
    }
    for i in 0..32 {
        acc = acc * 263 + code_hash[i] as Field;
    }
    acc
}

pub mod rlp_account;
