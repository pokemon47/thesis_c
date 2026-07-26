use crate::expanded_header_capacity::{expected_header_field_count, max_header_bytes, witness_version};
use crate::rlp::{parse_rlp_item, payload_byte};
use ::keccak256::keccak256;

pub fn verify_header_anchor(
    public_block_hash: [u8; 32],
    witness_version_input: Field,
    private_header_bytes: [u8; 640],
    private_header_len: Field,
) -> [u8; 32] {
    let header_len = private_header_len as u32;
    assert(private_header_len == header_len as Field);
    assert(witness_version_input == witness_version() as Field);
    assert(header_len > 0);
    assert(header_len <= max_header_bytes());

    for i in 0..640 {
        if i >= header_len {
            assert(private_header_bytes[i] == 0);
        }
    }

    assert(keccak256(private_header_bytes, header_len) == public_block_hash);

    let outer = parse_rlp_item(private_header_bytes, header_len, 0);
    assert(outer.is_list);
    assert(outer.encoded_offset == 0);
    assert(outer.encoded_len == header_len);

    let outer_payload_end = outer.payload_offset + outer.payload_len;
    let mut offset = outer.payload_offset;
    let mut state_root = [0; 32];

    for i in 0..20 {
        let field = parse_rlp_item(private_header_bytes, header_len, offset);
        assert(!field.is_list);
        if i == 3 {
            assert(field.payload_len == 32);
            for j in 0..32 {
                state_root[j] = payload_byte(private_header_bytes, field, j);
            }
        }
        offset = field.encoded_offset + field.encoded_len;
    }

    assert(expected_header_field_count() == 20);
    assert(offset == outer_payload_end);

    state_root
}

pub fn assert_header_anchor(
    public_block_hash: [u8; 32],
    public_expected_state_root: [u8; 32],
    witness_version_input: Field,
    private_header_bytes: [u8; 640],
    private_header_len: Field,
) {
    assert(
        verify_header_anchor(
            public_block_hash,
            witness_version_input,
            private_header_bytes,
            private_header_len,
        ) == public_expected_state_root
    );
}

#[test]
fn test_header_anchor_reconstructed_block_9_fixture() {
    let (header_bytes, header_len, block_hash, expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    assert_eq(
        verify_header_anchor(block_hash, witness_version() as Field, header_bytes, header_len),
        expected_state_root,
    );
}

#[test]
fn test_header_anchor_preserves_layout_variants() {
    let fixtures = [
        crate::header_fixtures::hoodi_block_9_reconstructed(),
        crate::header_fixtures::hoodi_block_9_extraData_2bytes(),
        crate::header_fixtures::hoodi_block_9_extraData_31bytes(),
    ];
    for fixture in fixtures {
        let (header_bytes, header_len, block_hash, expected_state_root) = fixture;
        assert_eq(
            verify_header_anchor(block_hash, witness_version() as Field, header_bytes, header_len),
            expected_state_root,
        );
    }
}

#[test(should_fail)]
fn test_header_anchor_wrong_public_block_hash_rejected() {
    let (header_bytes, header_len, _block_hash, expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    let mut wrong_block_hash = [0; 32];
    wrong_block_hash[31] = 1;
    assert_header_anchor(
        wrong_block_hash,
        expected_state_root,
        witness_version() as Field,
        header_bytes,
        header_len,
    );
}

#[test(should_fail)]
fn test_header_anchor_wrong_expected_state_root_rejected() {
    let (header_bytes, header_len, block_hash, _expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    let mut wrong_expected_state_root = [0; 32];
    wrong_expected_state_root[31] = 1;
    assert_header_anchor(
        block_hash,
        wrong_expected_state_root,
        witness_version() as Field,
        header_bytes,
        header_len,
    );
}

#[test(should_fail)]
fn test_header_anchor_mutated_active_header_byte_rejected() {
    let (mut header_bytes, header_len, block_hash, expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    header_bytes[12] ^= 1;
    assert_header_anchor(
        block_hash,
        expected_state_root,
        witness_version() as Field,
        header_bytes,
        header_len,
    );
}

#[test(should_fail)]
fn test_header_anchor_truncated_header_len_rejected() {
    let (header_bytes, header_len, block_hash, expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    assert_header_anchor(
        block_hash,
        expected_state_root,
        witness_version() as Field,
        header_bytes,
        header_len - 1,
    );
}

#[test(should_fail)]
fn test_header_anchor_zero_header_len_rejected() {
    let (header_bytes, _header_len, block_hash, expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    assert_header_anchor(
        block_hash,
        expected_state_root,
        witness_version() as Field,
        header_bytes,
        0,
    );
}

#[test(should_fail)]
fn test_header_anchor_nonzero_padding_rejected() {
    let (mut header_bytes, header_len, block_hash, expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    header_bytes[header_len as u32] = 1;
    assert_header_anchor(
        block_hash,
        expected_state_root,
        witness_version() as Field,
        header_bytes,
        header_len,
    );
}

#[test(should_fail)]
fn test_header_anchor_wrong_witness_version_rejected() {
    let (header_bytes, header_len, block_hash, expected_state_root) =
        crate::header_fixtures::hoodi_block_9_reconstructed();
    assert_header_anchor(
        block_hash,
        expected_state_root,
        2,
        header_bytes,
        header_len,
    );
}
