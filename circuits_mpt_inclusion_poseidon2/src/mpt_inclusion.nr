pub struct AuthenticatedTerminalValue {
    pub value_bytes: [u8; 256],
    pub value_len: Field,
}

fn as_u32(value: Field) -> u32 {
    let out = value as u32;
    assert(value == out as Field);
    out
}

fn byte_at(input: [u8; 1024], index: u32) -> u8 {
    assert(index < 1024);
    input[index]
}

fn item_zero(layout: [Field; 4]) {
    assert(layout == [0; 4]);
}

fn range_ok(layout: [Field; 4], node_len: u32) {
    let off = as_u32(layout[0]);
    let len = as_u32(layout[1]);
    let payload = as_u32(layout[2]);
    let payload_len = as_u32(layout[3]);
    assert(len > 0);
    assert(off + len <= node_len);
    assert(payload >= off);
    assert(payload + payload_len == off + len);
}

fn assert_rlp_string(input: [u8; 1024], layout: [Field; 4], node_len: u32) {
    range_ok(layout, node_len);
    let off = as_u32(layout[0]);
    let encoded_len = as_u32(layout[1]);
    let payload = as_u32(layout[2]);
    let payload_len = as_u32(layout[3]);
    let prefix = byte_at(input, off) as u32;
    if prefix < 0x80 {
        assert(encoded_len == 1);
        assert(payload == off);
        assert(payload_len == 1);
    } else if prefix <= 0xb7 {
        let length = prefix - 0x80;
        assert(payload_len == length);
        assert(encoded_len == length + 1);
        assert(payload == off + 1);
        if length == 1 {
            assert(byte_at(input, payload) >= 0x80);
        }
    } else {
        let lol = prefix - 0xb7;
        assert(lol >= 1);
        assert(lol <= 2);
        let length = if lol == 1 {
            let first = byte_at(input, off + 1) as u32;
            assert(first != 0);
            first
        } else {
            let hi = byte_at(input, off + 1) as u32;
            let lo = byte_at(input, off + 2) as u32;
            assert(hi != 0);
            hi * 256 + lo
        };
        assert(length > 55);
        assert(payload_len == length);
        assert(encoded_len == 1 + lol + length);
        assert(payload == off + 1 + lol);
    }
}

fn assert_rlp_list(input: [u8; 1024], layout: [Field; 4], node_len: u32) {
    range_ok(layout, node_len);
    let off = as_u32(layout[0]);
    let encoded_len = as_u32(layout[1]);
    let payload = as_u32(layout[2]);
    let payload_len = as_u32(layout[3]);
    let prefix = byte_at(input, off) as u32;
    if prefix < 0xf8 {
        assert(prefix >= 0xc0);
        let length = prefix - 0xc0;
        assert(payload_len == length);
        assert(encoded_len == length + 1);
        assert(payload == off + 1);
    } else {
        let lol = prefix - 0xf7;
        assert(lol >= 1);
        assert(lol <= 2);
        let length = if lol == 1 {
            let first = byte_at(input, off + 1) as u32;
            assert(first != 0);
            first
        } else {
            let hi = byte_at(input, off + 1) as u32;
            let lo = byte_at(input, off + 2) as u32;
            assert(hi != 0);
            hi * 256 + lo
        };
        assert(length > 55);
        assert(payload_len == length);
        assert(encoded_len == 1 + lol + length);
        assert(payload == off + 1 + lol);
    }
}

fn assert_bytes_equal(input: [u8; 1024], offset: u32, other: [u8; 32], other_len: u32) {
    for i in 0..1024 {
        if i < other_len {
            assert(byte_at(input, offset + i) == other[i]);
        }
    }
}

fn assert_compact(
    input: [u8; 1024],
    layout: [Field; 4],
    node_len: u32,
    key: [u8; 32],
    cursor: Field,
    expected_kind: u32,
) -> Field {
    assert_rlp_string(input, layout, node_len);
    let payload = as_u32(layout[2]);
    let payload_len = as_u32(layout[3]);
    assert(payload_len > 0);
    assert(payload_len <= 33);
    let first = byte_at(input, payload) as u32;
    let flags = first / 16;
    let odd = flags % 2;
    if expected_kind == 1 {
        assert(flags <= 1);
    } else {
        assert(flags >= 2);
        assert(flags <= 3);
    }
    if odd == 0 {
        assert(first % 16 == 0);
        assert(flags % 2 == 0);
    } else {
        assert(flags % 2 == 1);
    }
    let path_start = if odd == 1 { 1 } else { 2 };
    let path_len = payload_len * 2 - path_start;
    assert(path_len <= 64);
    let cursor_u32 = as_u32(cursor);
    assert(cursor_u32 + path_len <= 64);
    for i in 0..64 {
        if i < path_len {
            let nibble_index = path_start + i;
            let encoded = byte_at(input, payload + nibble_index / 2);
            let nibble = if nibble_index % 2 == 0 {
                (encoded / 16) as u32
            } else {
                (encoded % 16) as u32
            };
            assert(nibble == ((if (cursor_u32 + i) % 2 == 0 {
                key[(cursor_u32 + i) / 2] / 16
            } else {
                key[(cursor_u32 + i) / 2] % 16
            }) as u32));
        }
    }
    path_len as Field
}

fn check_terminal_buffer(
    input: [u8; 1024],
    layout: [Field; 4],
    node_len: u32,
    terminal_value: [u8; 256],
    terminal_value_len: Field,
) -> AuthenticatedTerminalValue {
    assert_rlp_string(input, layout, node_len);
    let off = as_u32(layout[2]);
    let len = as_u32(layout[3]);
    let supplied_len = as_u32(terminal_value_len);
    assert(supplied_len == len);
    assert(len > 0);
    assert(len <= 256);
    for i in 0..256 {
        if i < len {
            assert(terminal_value[i] == byte_at(input, off + i));
        } else {
            assert(terminal_value[i] == 0);
        }
    }
    AuthenticatedTerminalValue { value_bytes: terminal_value, value_len: terminal_value_len }
}

pub fn assert_inclusion(
    witness_version: Field,
    public_state_root: [u8; 32],
    private_state_root_field: Field,
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
) -> AuthenticatedTerminalValue {
    let count = as_u32(active_node_count);
    assert(count >= 1);
    assert(count <= crate::expanded_mpt_capacity::max_proof_nodes());
    assert(witness_version == crate::expanded_mpt_capacity::witness_version() as Field);
    let value_len = as_u32(terminal_value_len);
    assert(value_len <= crate::expanded_mpt_capacity::max_terminal_value_bytes());
    assert(crate::hash_poseidon2::bytes32_to_field(public_state_root) == private_state_root_field);
    assert(crate::hash_poseidon2::hash_node(node_bytes[0], node_lengths[0]) == private_state_root_field);

    let mut total_bytes = 0;
    let mut cursor: Field = 0;
    let mut extension_count = 0;
    let mut result = AuthenticatedTerminalValue { value_bytes: [0; 256], value_len: 0 };
    for i in 0..16 {
        let node_len = as_u32(node_lengths[i]);
        assert(node_lengths[i] == node_len as Field);
        if i < count {
            assert(node_len > 0);
            assert(node_len <= crate::expanded_mpt_capacity::max_node_rlp_bytes());
            for j in 0..1024 { if j >= node_len { assert(node_bytes[i][j] == 0); } }
            total_bytes += node_len;
            assert(total_bytes <= crate::expanded_mpt_capacity::max_total_proof_rlp_bytes());
            assert_rlp_list(node_bytes[i], node_list_layouts[i], node_len);
            assert(node_list_layouts[i][0] == 0);
            assert(node_list_layouts[i][1] == node_len as Field);
            let kind = as_u32(node_kinds[i]);
            assert(node_kinds[i] == kind as Field);
            assert(kind <= 2);
            if kind == 1 {
                extension_count += 1;
                assert(extension_count <= crate::expanded_mpt_capacity::max_extension_nodes());
                if i > 0 { assert(node_kinds[i - 1] != 1); }
            }
            for j in 0..17 {
                if kind == 0 {
                    assert_rlp_string(node_bytes[i], node_item_layouts[i][j], node_len);
                } else {
                    if j < 2 {
                        assert_rlp_string(node_bytes[i], node_item_layouts[i][j], node_len);
                    } else {
                        item_zero(node_item_layouts[i][j]);
                    }
                }
                if kind == 0 {
                    if j == 0 {
                        assert(node_item_layouts[i][j][0] == node_list_layouts[i][2]);
                    } else {
                        assert(node_item_layouts[i][j][0] == node_item_layouts[i][j - 1][0] + node_item_layouts[i][j - 1][1]);
                    }
                } else {
                    if j < 2 {
                        if j == 0 {
                            assert(node_item_layouts[i][j][0] == node_list_layouts[i][2]);
                        } else {
                            assert(node_item_layouts[i][j][0] == node_item_layouts[i][j - 1][0] + node_item_layouts[i][j - 1][1]);
                        }
                    }
                }
            }
            if kind == 0 {
                assert(node_item_layouts[i][16][0] + node_item_layouts[i][16][1] == node_list_layouts[i][2] + node_list_layouts[i][3]);
            } else {
                assert(node_item_layouts[i][1][0] + node_item_layouts[i][1][1] == node_list_layouts[i][2] + node_list_layouts[i][3]);
            }
            let path_len: Field = if kind == 0 {
                assert(node_kinds[i] == 0);
                if i + 1 == count {
                    assert(as_u32(cursor) == 64);
                    result = check_terminal_buffer(node_bytes[i], node_item_layouts[i][16], node_len, terminal_value, terminal_value_len);
                    0
                } else {
                    let c = as_u32(cursor);
                    assert(c < 64);
                    let index = if c % 2 == 0 { (trie_key[c / 2] / 16) as u32 } else { (trie_key[c / 2] % 16) as u32 };
                    assert(index < 16);
                    assert(selected_ref_layouts[i] == node_item_layouts[i][index]);
                    index as Field
                }
            } else {
                let expected = kind;
                assert(node_compact_layouts[i] == node_item_layouts[i][0]);
                let suffix = assert_compact(node_bytes[i], node_compact_layouts[i], node_len, trie_key, cursor, expected);
                if kind == 2 {
                    assert(i + 1 == count);
                    assert(as_u32(cursor) + as_u32(suffix) == 64);
                    result = check_terminal_buffer(node_bytes[i], node_item_layouts[i][1], node_len, terminal_value, terminal_value_len);
                } else {
                    assert(i + 1 < count);
                }
                suffix
            };
            if kind == 2 {
                cursor = cursor + path_len;
                let leaf_cursor = as_u32(cursor);
                assert(cursor == leaf_cursor as Field);
                assert(leaf_cursor == 64);
            }
            let has_child: u32 = if kind == 1 {
                1
            } else {
                if kind == 0 {
                    if i + 1 < count { 1 } else { 0 }
                } else { 0 }
            };
            if has_child == 1 {
                if kind == 1 {
                    assert(selected_ref_layouts[i] == node_item_layouts[i][1]);
                }
                let ref_len = as_u32(selected_ref_lengths[i]);
                let ref_kind = as_u32(selected_ref_kinds[i]);
                assert(selected_ref_lengths[i] == ref_len as Field);
                assert(selected_ref_kinds[i] == ref_kind as Field);
                assert(ref_len > 0);
                assert(ref_len <= 32);
                assert(ref_len > 0);
                assert(selected_ref_layouts[i][3] == ref_len as Field);
                for j in 0..32 {
                    if j < ref_len {
                        assert(selected_ref_bytes[i][j] == byte_at(node_bytes[i], as_u32(selected_ref_layouts[i][2]) + j));
                    } else {
                        assert(selected_ref_bytes[i][j] == 0);
                    }
                }
                if ref_len < 32 {
                    assert(ref_kind == 1);
                    assert(node_lengths[i + 1] == ref_len as Field);
                    assert_bytes_equal(node_bytes[i + 1], 0, selected_ref_bytes[i], ref_len);
                } else {
                    assert(ref_kind == 2);
                    assert(crate::hash_poseidon2::hash_node(node_bytes[i + 1], node_lengths[i + 1]) == crate::hash_poseidon2::bytes32_to_field(selected_ref_bytes[i]));
                }
                cursor = cursor + (if kind == 0 { 1 } else { as_u32(path_len) }) as Field;
                let cursor_u32 = as_u32(cursor);
                assert(cursor == cursor_u32 as Field);
                assert(cursor_u32 <= 64);
            }
        } else {
            assert(node_lengths[i] == 0);
            assert(node_kinds[i] == 0);
            assert(node_list_layouts[i] == [0; 4]);
            assert(node_compact_layouts[i] == [0; 4]);
            assert(selected_ref_layouts[i] == [0; 4]);
            assert(selected_ref_bytes[i] == [0; 32]);
            assert(selected_ref_lengths[i] == 0);
            assert(selected_ref_kinds[i] == 0);
            for j in 0..1024 { assert(node_bytes[i][j] == 0); }
            for j in 0..17 { assert(node_item_layouts[i][j] == [0; 4]); }
        }
    }
    assert(as_u32(cursor) == 64);
    result
}

fn root_leaf_fixture() -> ([u8; 1024], [Field; 4], [Field; 4], [Field; 4]) {
    let mut node = [0; 1024];
    node[0] = 0xe3; node[1] = 0xa1; node[2] = 0x20; node[35] = 0x78;
    (node, [0, 36, 1, 35], [1, 34, 2, 33], [35, 1, 35, 1])
}

#[test]
fn test_poseidon2_root_leaf_inclusion() {
    let (node, list, compact, value) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    let root_bytes = [
        0x2f, 0x68, 0x6c, 0x8f, 0xbf, 0x8a, 0x4d, 0x52,
        0x7d, 0x03, 0x42, 0xe9, 0x62, 0x77, 0x56, 0x97,
        0x15, 0xf9, 0x4d, 0x7e, 0x0c, 0x87, 0xd6, 0xff,
        0x1d, 0xcf, 0xd4, 0xe9, 0x7f, 0x59, 0x37, 0x94,
    ];
    let root = crate::hash_poseidon2::bytes32_to_field(root_bytes);
    assert_inclusion(
        1, root_bytes, root, [0; 32], 1, nodes, lengths, kinds, lists, items,
        compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1,
    );
}

#[test(should_fail)]
fn test_poseidon2_wrong_root_field_fails() {
    let (node, list, compact, value) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, [0; 32], 1, [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

fn poseidon_branch_leaf_fixture() -> ([u8; 1024], [u8; 1024], [u8; 32]) {
    let mut leaf = [0; 1024];
    leaf[0] = 0xe2; leaf[1] = 0xa0; leaf[2] = 0x30; leaf[34] = 0x78;
    let leaf_hash_field = crate::hash_poseidon2::hash_node(leaf, 35);
    let leaf_hash_bytes = [
        0x07, 0xf4, 0x50, 0x90, 0x43, 0xd7, 0x52, 0x48,
        0xe3, 0xa6, 0x5e, 0x26, 0xb0, 0x95, 0x6d, 0xf5,
        0xf3, 0xce, 0x3f, 0x70, 0x1e, 0x2c, 0xfb, 0x36,
        0xab, 0xef, 0x0c, 0x8a, 0x05, 0x5d, 0x13, 0xbc,
    ];
    assert(leaf_hash_field == crate::hash_poseidon2::bytes32_to_field(leaf_hash_bytes));
    let mut branch = [0; 1024];
    branch[0] = 0xf1; branch[1] = 0xa0;
    for i in 0..32 { branch[2 + i] = leaf_hash_bytes[i]; }
    for i in 0..16 { branch[34 + i] = 0x80; }
    (branch, leaf, leaf_hash_bytes)
}

#[test]
fn test_poseidon2_hashed_branch_to_leaf_inclusion() {
    let (branch, leaf, leaf_hash) = poseidon_branch_leaf_fixture();
    let root_bytes = [
        0x1f, 0xfb, 0xfb, 0x38, 0x36, 0x38, 0x6f, 0xd7,
        0x87, 0x0c, 0x00, 0x3f, 0x58, 0xdb, 0xfa, 0x4c,
        0xba, 0x59, 0xa6, 0x73, 0x5e, 0x47, 0xbe, 0x71,
        0x35, 0xeb, 0x2b, 0x11, 0x50, 0x10, 0x6c, 0x5f,
    ];
    let mut nodes = [[0; 1024]; 16]; nodes[0] = branch; nodes[1] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 50; lengths[1] = 35;
    let mut kinds = [0; 16]; kinds[0] = 0; kinds[1] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 50, 1, 49]; lists[1] = [0, 35, 1, 34];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = [1, 33, 2, 32];
    for i in 1..17 { items[0][i] = [(33 + i) as Field, 1, (34 + i) as Field, 0]; }
    items[1][0] = [1, 33, 2, 32]; items[1][1] = [34, 1, 34, 1];
    let mut compacts = [[0; 4]; 16]; compacts[1] = items[1][0];
    let mut refs = [[0; 32]; 16]; refs[0] = leaf_hash;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 32;
    let mut ref_kinds = [0; 16]; ref_kinds[0] = 2;
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][0];
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, root_bytes, crate::hash_poseidon2::bytes32_to_field(root_bytes), [0; 32], 2, nodes, lengths, kinds, lists, items, compacts, ref_layouts, refs, ref_lengths, ref_kinds, terminal, 1);
}

#[test]
fn test_poseidon2_max_shaped_canonical_branch_boundary_inclusion() {
    let terminal_value_len = crate::expanded_mpt_capacity::max_terminal_value_bytes() as Field;
    let final_branch_len = 3 + (16 * 33) + 3 + terminal_value_len;
    let mut final_branch = [0; 1024];
    final_branch[0] = 0xf9;
    final_branch[1] = 0x03;
    final_branch[2] = 0x13;
    for slot in 0..16 {
        let start = 3 + slot * 33;
        final_branch[start] = 0xa0;
        for j in 0..32 {
            final_branch[start + 1 + j] = (slot * 17 + j) as u8;
        }
    }
    let value_start = 3 + 16 * 33;
    final_branch[value_start] = 0xb9;
    final_branch[value_start + 1] = 0x01;
    final_branch[value_start + 2] = 0x00;
    let mut terminal_buf = [0; 256];
    for i in 0..256 {
        terminal_buf[i] = i as u8;
        final_branch[value_start + 3 + i] = terminal_buf[i];
    }
    let final_branch_hash_bytes = [
        0x06, 0xeb, 0xda, 0x43, 0xbb, 0x39, 0x95, 0x11,
        0xa5, 0xed, 0x4b, 0x6b, 0x94, 0x23, 0x54, 0xbb,
        0x2b, 0x22, 0x8e, 0xfd, 0x76, 0x39, 0x6b, 0x88,
        0x01, 0xfb, 0xdd, 0x20, 0xa6, 0x1f, 0xd2, 0x9e,
    ];

    let mut root_extension = [0; 1024];
    root_extension[0] = 0xf8;
    root_extension[1] = 0x43;
    root_extension[2] = 0xa1;
    root_extension[3] = 0x00;
    for i in 0..32 { root_extension[4 + i] = 0x00; }
    root_extension[36] = 0xa0;
    for i in 0..32 { root_extension[37 + i] = final_branch_hash_bytes[i]; }

    let mut nodes = [[0; 1024]; 16];
    nodes[0] = root_extension;
    nodes[1] = final_branch;
    let mut lengths: [Field; 16] = [0; 16];
    lengths[0] = 69;
    lengths[1] = final_branch_len;
    let mut kinds: [Field; 16] = [0; 16];
    kinds[0] = 1;
    kinds[1] = 0;
    let mut lists: [[Field; 4]; 16] = [[0; 4]; 16];
    lists[0] = [0, 69, 2, 67];
    lists[1] = [0, final_branch_len, 3, final_branch_len - 3];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = [2, 34, 3, 33];
    items[0][1] = [36, 33, 37, 32];
    items[1][0] = [3, 33, 4, 32];
    for slot in 1..16 {
        let start = 3 + slot * 33;
        items[1][slot] = [start as Field, 33, (start + 1) as Field, 32];
    }
    items[1][16] = [
        value_start as Field,
        (3 + terminal_value_len) as Field,
        (value_start + 3) as Field,
        terminal_value_len,
    ];
    let mut compacts: [[Field; 4]; 16] = [[0; 4]; 16];
    compacts[0] = items[0][0];
    let mut refs = [[0; 32]; 16];
    refs[0] = final_branch_hash_bytes;
    let mut ref_lengths: [Field; 16] = [0; 16];
    ref_lengths[0] = 32;
    let mut ref_kinds: [Field; 16] = [0; 16];
    ref_kinds[0] = 2;
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16];
    ref_layouts[0] = items[0][1];

    let root_bytes = [
        0x10, 0x47, 0x80, 0x30, 0x1f, 0xa8, 0xb8, 0xce,
        0x48, 0x13, 0xdb, 0x82, 0x95, 0x50, 0x6e, 0xb7,
        0x87, 0xae, 0x67, 0x51, 0x03, 0x3d, 0x1e, 0x1b,
        0x75, 0xe5, 0x69, 0xdb, 0xfa, 0xa4, 0xe5, 0x37,
    ];
    let root = crate::hash_poseidon2::bytes32_to_field(root_bytes);
    assert(as_u32(final_branch_len) == 790);
    assert(as_u32(final_branch_len) == crate::expanded_mpt_capacity::max_node_rlp_bytes() - 234);
    assert_inclusion(
        1,
        root_bytes,
        root,
        [0; 32],
        2,
        nodes,
        lengths,
        kinds,
        lists,
        items,
        compacts,
        ref_layouts,
        refs,
        ref_lengths,
        ref_kinds,
        terminal_buf,
        terminal_value_len as Field,
    );
}

#[test]
fn test_poseidon2_extension_to_inline_leaf_inclusion() {
    let mut leaf = [0; 1024]; leaf[0] = 0xc2; leaf[1] = 0x20; leaf[2] = 0x78;
    let mut extension = [0; 1024]; extension[0] = 0xe6; extension[1] = 0xa1; extension[2] = 0x00;
    for i in 0..32 { extension[3 + i] = 0; }
    extension[35] = 0x83; extension[36] = 0xc2; extension[37] = 0x20; extension[38] = 0x78;
    let root_bytes = [
        0x01, 0x7c, 0xf4, 0x03, 0x8d, 0x95, 0xbe, 0xf0,
        0xea, 0xb9, 0x2d, 0x92, 0x00, 0x50, 0x1f, 0x13,
        0x11, 0x83, 0x80, 0x8b, 0xa5, 0xd8, 0x95, 0x4a,
        0xb0, 0x39, 0xe5, 0xa2, 0xd8, 0xc8, 0x7e, 0x13,
    ];
    let mut nodes = [[0; 1024]; 16]; nodes[0] = extension; nodes[1] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 39; lengths[1] = 3;
    let mut kinds = [0; 16]; kinds[0] = 1; kinds[1] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 39, 1, 38]; lists[1] = [0, 3, 1, 2];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = [1, 34, 2, 33]; items[0][1] = [35, 4, 36, 3];
    items[1][0] = [1, 1, 1, 1]; items[1][1] = [2, 1, 2, 1];
    let mut compacts = [[0; 4]; 16]; compacts[0] = items[0][0]; compacts[1] = items[1][0];
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][1];
    let mut ref_bytes = [[0; 32]; 16]; ref_bytes[0][0] = 0xc2; ref_bytes[0][1] = 0x20; ref_bytes[0][2] = 0x78;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 3;
    let mut ref_kinds = [0; 16]; ref_kinds[0] = 1;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, root_bytes, crate::hash_poseidon2::bytes32_to_field(root_bytes), [0; 32], 2, nodes, lengths, kinds, lists, items, compacts, ref_layouts, ref_bytes, ref_lengths, ref_kinds, terminal, 1);
}

#[test]
fn test_poseidon2_extension_to_branch_value_terminal_inclusion() {
    let mut branch = [0; 1024]; branch[0] = 0xd1;
    for i in 0..16 { branch[1 + i] = 0x80; }
    branch[17] = 0x78;
    let mut extension = [0; 1024]; extension[0] = 0xf5; extension[1] = 0xa1; extension[2] = 0x00;
    for i in 0..32 { extension[3 + i] = 0; }
    extension[35] = 0x92; extension[36] = 0xd1;
    for i in 0..16 { extension[37 + i] = 0x80; }
    extension[53] = 0x78;
    let root_bytes = [
        0x1d, 0xd6, 0x00, 0x6c, 0x6e, 0xe9, 0xbc, 0x8b,
        0x05, 0x30, 0x3f, 0xf2, 0xbb, 0x24, 0x12, 0xa4,
        0x9a, 0xec, 0xbb, 0x3a, 0x00, 0xe8, 0x98, 0xcb,
        0xf0, 0xbe, 0x60, 0x76, 0x86, 0x86, 0xa4, 0xc4,
    ];
    let mut nodes = [[0; 1024]; 16]; nodes[0] = extension; nodes[1] = branch;
    let mut lengths = [0; 16]; lengths[0] = 54; lengths[1] = 18;
    let mut kinds = [0; 16]; kinds[0] = 1; kinds[1] = 0;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 54, 1, 53]; lists[1] = [0, 18, 1, 17];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = [1, 34, 2, 33]; items[0][1] = [35, 19, 36, 18];
    for i in 0..16 { items[1][i] = [(1 + i) as Field, 1, (2 + i) as Field, 0]; }
    items[1][16] = [17, 1, 17, 1];
    let mut compacts = [[0; 4]; 16]; compacts[0] = items[0][0];
    let mut ref_bytes = [[0; 32]; 16]; ref_bytes[0][0] = 0xd1;
    for i in 0..16 { ref_bytes[0][1 + i] = 0x80; }
    ref_bytes[0][17] = 0x78;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 18;
    let mut ref_kinds = [0; 16]; ref_kinds[0] = 1;
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][1];
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(
        1, root_bytes, crate::hash_poseidon2::bytes32_to_field(root_bytes), [0; 32], 2,
        nodes, lengths, kinds, lists, items, compacts, ref_layouts, ref_bytes,
        ref_lengths, ref_kinds, terminal, 1,
    );
}

#[test]
fn test_poseidon2_branch_to_extension_to_inline_leaf_inclusion() {
    let mut leaf = [0; 1024]; leaf[0] = 0xc2; leaf[1] = 0x20; leaf[2] = 0x78;
    let mut extension = [0; 1024]; extension[0] = 0xe5; extension[1] = 0xa0; extension[2] = 0x10;
    for i in 0..31 { extension[3 + i] = 0; }
    extension[34] = 0x83; extension[35] = 0xc2; extension[36] = 0x20; extension[37] = 0x78;
    let extension_hash = crate::hash_poseidon2::hash_node(extension, 38);
    let mut branch = [0; 1024]; branch[0] = 0xf1; branch[1] = 0xa0;
    let extension_hash_bytes = [0x1c,0x59,0xb1,0x00,0x13,0xf1,0x2c,0x23,0x46,0x3c,0xe2,0xa8,0x03,0x16,0x70,0xb5,0xf0,0xf9,0xd8,0xd3,0xb8,0xf0,0x63,0xf3,0xd4,0xab,0x92,0x42,0x58,0x31,0x2e,0x49];
    for i in 0..32 { branch[2 + i] = extension_hash_bytes[i]; }
    for i in 0..16 { branch[34 + i] = 0x80; }
    let root_bytes = [0x26,0xde,0xa0,0xa6,0xfd,0x89,0xc0,0x9d,0x3c,0x84,0x95,0xdf,0xfa,0x87,0x44,0x1f,0xfd,0xc8,0x8d,0x55,0x9a,0xd9,0xb2,0x07,0x99,0xe5,0xf7,0xa5,0x29,0x71,0x02,0x6e];
    let mut nodes = [[0; 1024]; 16]; nodes[0] = branch; nodes[1] = extension; nodes[2] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 50; lengths[1] = 38; lengths[2] = 3;
    let mut kinds = [0; 16]; kinds[0] = 0; kinds[1] = 1; kinds[2] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0,50,1,49]; lists[1] = [0,38,1,37]; lists[2] = [0,3,1,2];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16]; items[0][0] = [1,33,2,32];
    for i in 1..17 { items[0][i] = [(33+i) as Field,1,(34+i) as Field,0]; }
    items[1][0] = [1,33,2,32]; items[1][1] = [34,4,35,3]; items[2][0] = [1,1,1,1]; items[2][1] = [2,1,2,1];
    let mut compacts = [[0;4];16]; compacts[1]=items[1][0]; compacts[2]=items[2][0];
    let mut ref_layouts: [[Field;4];16]=[[0;4];16]; ref_layouts[0]=items[0][0]; ref_layouts[1]=items[1][1];
    let mut ref_bytes=[[0;32];16]; for i in 0..32 { ref_bytes[0][i]=extension_hash_bytes[i]; } ref_bytes[1][0]=0xc2; ref_bytes[1][1]=0x20; ref_bytes[1][2]=0x78;
    let mut ref_lengths=[0;16]; ref_lengths[0]=32; ref_lengths[1]=3; let mut ref_kinds=[0;16]; ref_kinds[0]=2; ref_kinds[1]=1;
    let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, root_bytes, crate::hash_poseidon2::bytes32_to_field(root_bytes), [0;32], 3, nodes, lengths, kinds, lists, items, compacts, ref_layouts, ref_bytes, ref_lengths, ref_kinds, terminal, 1);
}

#[test]
fn test_poseidon2_terminal_value_near_generated_capacity() {
    let value_len = crate::expanded_mpt_capacity::max_terminal_value_bytes() - 1;
    let mut node = [0; 1024]; node[0] = 0xf9; node[1] = 0x01; node[2] = 0x23; node[3] = 0xa1; node[4] = 0x20;
    for i in 0..255 { node[39 + i] = (i as u8) + 1; }
    node[37] = 0xb8; node[38] = 0xff;
    let root_bytes = [0x0a,0x59,0x19,0x38,0x3a,0x8a,0x46,0x64,0x96,0x8c,0x17,0xbf,0x91,0xd6,0x14,0x86,0x52,0x43,0xcc,0x8a,0xbe,0x18,0xb2,0xb7,0x3e,0x93,0xe9,0x48,0x11,0x4c,0xa4,0xd6];
    let mut nodes=[[0;1024];16]; nodes[0]=node; let mut lengths=[0;16]; lengths[0]=294; let mut kinds=[0;16]; kinds[0]=2;
    let mut lists=[[0;4];16]; lists[0]=[0,294,3,291]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[3,34,4,33]; items[0][1]=[37,257,39,255];
    let mut compacts=[[0;4];16]; compacts[0]=items[0][0]; let mut terminal=[0;256]; for i in 0..255 { terminal[i]=(i as u8)+1; }
    assert_inclusion(1, root_bytes, crate::hash_poseidon2::bytes32_to_field(root_bytes), [0;32], 1, nodes, lengths, kinds, lists, items, compacts, [[0;4];16], [[0;32];16], [0;16], [0;16], terminal, value_len as Field);
}

fn assert_node_length_capacity(length: Field) { assert(as_u32(length) <= crate::expanded_mpt_capacity::max_node_rlp_bytes()); }
fn assert_total_length_capacity(length: Field) { assert(as_u32(length) <= crate::expanded_mpt_capacity::max_total_proof_rlp_bytes()); }

#[test]
fn test_poseidon2_multiple_extensions_separated_by_branch() {
    let mut leaf=[0;1024]; leaf[0]=0xdd; leaf[1]=0x9b; leaf[2]=0x20; for i in 0..26 { leaf[3+i]=0; } leaf[29]=0x78;
    let mut extension2=[0;1024]; extension2[0]=0xe6; extension2[1]=0x86; extension2[2]=0x00; for i in 0..5 { extension2[3+i]=0; } extension2[8]=0x9e; for i in 0..30 { extension2[9+i]=leaf[i]; }
    let ext2_hash_bytes=[0x26,0xf1,0xe5,0xa9,0xcc,0x63,0x83,0x8c,0x24,0x3b,0x24,0x52,0x9e,0x74,0x32,0x0e,0x39,0x0a,0x0d,0x96,0xda,0xd7,0x22,0x68,0x59,0x63,0x08,0xf6,0xb8,0x93,0xa8,0x12];
    let mut branch=[0;1024]; branch[0]=0xf1; branch[1]=0xa0; for i in 0..32 { branch[2+i]=ext2_hash_bytes[i]; } for i in 0..16 { branch[34+i]=0x80; }
    let branch_hash_bytes=[0x25,0x80,0x5c,0x34,0x5c,0xc6,0x88,0x80,0x39,0xfe,0x05,0x79,0x3a,0x43,0xe3,0x22,0xd8,0xbf,0x5b,0xe2,0x2e,0xbc,0xa1,0x1c,0x7a,0x01,0x72,0x0b,0xbd,0x20,0x49,0x7d];
    let mut extension1=[0;1024]; extension1[0]=0xe2; extension1[1]=0x10; extension1[2]=0xa0; for i in 0..32 { extension1[3+i]=branch_hash_bytes[i]; }
    let root_bytes=[0x1a,0x97,0xcc,0xd5,0x17,0x32,0x92,0x07,0x55,0xce,0x8f,0x47,0x2c,0xcc,0xba,0x44,0x0b,0x5c,0x19,0xe9,0x9e,0x1c,0xde,0x11,0xf4,0x58,0x37,0xc6,0xb4,0x89,0x28,0xda];
    let mut nodes=[[0;1024];16]; nodes[0]=extension1; nodes[1]=branch; nodes[2]=extension2; nodes[3]=leaf; let mut lengths=[0;16]; lengths[0]=35; lengths[1]=50; lengths[2]=39; lengths[3]=30; let mut kinds=[0;16]; kinds[0]=1; kinds[1]=0; kinds[2]=1; kinds[3]=2;
    let mut lists=[[0;4];16]; lists[0]=[0,35,1,34]; lists[1]=[0,50,1,49]; lists[2]=[0,39,1,38]; lists[3]=[0,30,1,29]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[1,1,1,1]; items[0][1]=[2,33,3,32]; items[1][0]=[1,33,2,32]; for i in 1..17 { items[1][i]=[(33+i) as Field,1,(34+i) as Field,0]; } items[2][0]=[1,7,2,6]; items[2][1]=[8,31,9,30]; items[3][0]=[1,28,2,27]; items[3][1]=[29,1,29,1];
    let mut compacts=[[0;4];16]; compacts[0]=items[0][0]; compacts[2]=items[2][0]; compacts[3]=items[3][0]; let mut ref_layouts: [[Field;4];16]=[[0;4];16]; ref_layouts[0]=items[0][1]; ref_layouts[1]=items[1][0]; ref_layouts[2]=items[2][1]; let mut refs=[[0;32];16]; refs[0]=branch_hash_bytes; refs[1]=ext2_hash_bytes; for i in 0..30 { refs[2][i]=leaf[i]; } let mut ref_lengths=[0;16]; ref_lengths[0]=32; ref_lengths[1]=32; ref_lengths[2]=30; let mut ref_kinds=[0;16]; ref_kinds[0]=2; ref_kinds[1]=2; ref_kinds[2]=1; let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, root_bytes, crate::hash_poseidon2::bytes32_to_field(root_bytes), [0;32], 4, nodes,lengths,kinds,lists,items,compacts,ref_layouts,refs,ref_lengths,ref_kinds,terminal,1);
}

#[test]
fn test_poseidon2_maximum_active_branch_chain_with_zero_padding() {
    let mut leaf=[0;1024]; leaf[0]=0xdb; leaf[1]=0x99; leaf[2]=0x30; for i in 0..24 { leaf[3+i]=0; } leaf[27]=0x78;
    let hashes: [[u8;32];15]=[
        [0x19,0x2d,0xa1,0x30,0x08,0x83,0xa5,0x82,0x6f,0x56,0xda,0x10,0xca,0xbd,0x0a,0x28,0x0c,0xae,0xab,0x19,0x20,0xf2,0xf9,0x27,0x0d,0x87,0x49,0x4f,0x58,0x73,0x82,0xa8],
        [0x16,0x01,0x02,0x54,0x26,0xef,0x3f,0xdf,0xcc,0xf1,0x78,0x32,0xdb,0xe2,0x5d,0xd7,0x5c,0x6c,0xd4,0x68,0x7b,0xa2,0x0e,0xde,0xe8,0xfa,0xaf,0x50,0xc9,0xca,0xe1,0x83],
        [0x2b,0x7e,0x9a,0x72,0xb4,0x82,0x5c,0x1d,0x5c,0x4b,0x8c,0x7e,0xab,0x29,0x1c,0x51,0x18,0xa1,0xbe,0x47,0x87,0xa2,0xff,0xa5,0x5e,0x9f,0xde,0x5a,0x92,0xe5,0x09,0x41],
        [0x03,0x8f,0x8a,0xcf,0xf6,0xb9,0x94,0x59,0x21,0x28,0xa6,0x24,0xbd,0x7f,0x5c,0x84,0xd1,0x4e,0xd8,0xf5,0x68,0x6f,0xec,0x6d,0x64,0x12,0x1b,0x17,0xfe,0x5a,0x90,0x94],
        [0x11,0x41,0x60,0x13,0x11,0xab,0xf4,0x41,0x0c,0xb6,0xcc,0xdf,0xc6,0x45,0x48,0x18,0x09,0xb8,0xb6,0xd2,0xa4,0x64,0x8b,0xdc,0xad,0x6f,0x35,0xcd,0x9a,0xee,0x40,0x5b],
        [0x30,0x20,0x84,0x1a,0x96,0x29,0x88,0xeb,0x7f,0x80,0x0a,0x03,0x86,0x78,0x88,0xc1,0x8c,0xf6,0x55,0x1e,0x9c,0x0d,0xdf,0x85,0xdd,0xd0,0xa0,0x43,0x37,0xdf,0x41,0x9f],
        [0x03,0xf9,0xa7,0x9b,0xd5,0x1f,0xd9,0xf8,0x82,0xc9,0x2d,0x9f,0x0f,0x1f,0xd6,0xa0,0x8a,0x0a,0xe9,0x7a,0x07,0xca,0xd5,0x66,0xa4,0x70,0xe9,0x6e,0x2e,0x0d,0x13,0xc3],
        [0x13,0x29,0xe6,0x7c,0x30,0x06,0xeb,0x38,0x48,0xdb,0x0c,0x66,0xcc,0xa4,0x14,0xa0,0x8b,0xaa,0x82,0xdb,0x0c,0x10,0x6e,0x2b,0xf4,0xa5,0x16,0x74,0xca,0xd6,0xb2,0x77],
        [0x17,0x35,0x28,0x77,0x2e,0xf0,0xcd,0xcb,0x15,0xfb,0x7c,0x19,0x91,0x97,0xd5,0x8d,0xb3,0x9a,0x7a,0x81,0x41,0x9b,0x6f,0xc0,0xd7,0xbd,0x42,0x24,0x29,0x29,0x22,0xf5],
        [0x04,0xdc,0x49,0x76,0x81,0x31,0x82,0xda,0x3e,0x7e,0xeb,0xd4,0x65,0x05,0x61,0xd8,0x83,0xa8,0x0e,0xe3,0xee,0x2c,0x69,0x9a,0xd0,0x93,0xb7,0x5a,0x04,0xef,0xde,0x22],
        [0x1a,0x51,0x19,0xf0,0x9c,0xfb,0xae,0xdd,0x45,0x59,0xba,0x81,0x7d,0xc9,0x33,0xbe,0xd1,0xd8,0x8c,0xf8,0x6c,0x0a,0x78,0xa9,0xe1,0xa7,0x85,0x89,0xac,0x1e,0x2d,0xe5],
        [0x11,0x85,0xe2,0xfb,0x4a,0xf5,0x58,0x1f,0x65,0xe8,0x78,0x45,0xe2,0xb3,0x3d,0x57,0x6f,0x14,0xd2,0xa3,0xcc,0x74,0x90,0x73,0xbd,0x04,0x71,0x4b,0xf5,0xd4,0x0e,0x04],
        [0x08,0xa6,0x76,0xe1,0x38,0x72,0x42,0x62,0xf1,0x4d,0xcf,0xee,0xa5,0x78,0x5c,0x30,0x32,0x7d,0x39,0xfb,0xe9,0x0d,0x00,0x37,0xa8,0x4b,0x60,0x1c,0xe9,0xfe,0xa4,0x7d],
        [0x02,0x19,0xb9,0xed,0xef,0xc1,0xc4,0x93,0x02,0x28,0x8d,0xff,0x5b,0x8e,0x8c,0xc4,0x1b,0x4c,0x24,0x61,0x8f,0x23,0x3f,0x17,0x6d,0xdf,0x65,0xc6,0x3e,0xcc,0x3a,0xcf],
        [0x14,0x83,0xe6,0x0d,0x10,0x1c,0xa6,0x77,0x6f,0xfc,0xed,0x28,0x5a,0xb4,0xd6,0x2e,0x7b,0x8b,0xbf,0xff,0x98,0xb9,0x7b,0xf7,0x32,0x5a,0xdd,0x3a,0x01,0xdd,0xfc,0xed],
    ];
    let mut nodes=[[0;1024];16]; nodes[15]=leaf; let mut lengths=[0;16]; lengths[15]=28; let mut kinds=[0;16]; kinds[15]=2;
    for k in 0..15 { let idx=14-k; let mut branch=[0;1024]; if idx==14 { branch[0]=0xed; branch[1]=0x9c; for j in 0..28 { branch[2+j]=nodes[15][j]; } for j in 0..16 { branch[30+j]=0x80; } lengths[idx]=46; } else { branch[0]=0xf1; branch[1]=0xa0; for j in 0..32 { branch[2+j]=hashes[idx+1][j]; } for j in 0..16 { branch[34+j]=0x80; } lengths[idx]=50; } nodes[idx]=branch; kinds[idx]=0; }
    let mut lists=[[0;4];16]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; let mut compacts=[[0;4];16]; let mut refs=[[0;32];16]; let mut ref_lengths=[0;16]; let mut ref_kinds=[0;16]; let mut ref_layouts: [[Field;4];16]=[[0;4];16];
    for i in 0..15 { lists[i]=[0,lengths[i],1,lengths[i]-1]; if i==14 { items[i][0]=[1,29,2,28]; ref_lengths[i]=28; ref_kinds[i]=1; for j in 0..28 { refs[i][j]=nodes[15][j]; } } else { items[i][0]=[1,33,2,32]; ref_lengths[i]=32; ref_kinds[i]=2; refs[i]=hashes[i+1]; } ref_layouts[i]=items[i][0]; let empty_start=if i==14 {30} else {34}; for j in 1..17 { items[i][j]=[(empty_start+j-1) as Field,1,(empty_start+j) as Field,0]; } }
    lists[15]=[0,28,1,27]; items[15][0]=[1,26,2,25]; items[15][1]=[27,1,27,1]; compacts[15]=items[15][0]; let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, hashes[0], crate::hash_poseidon2::bytes32_to_field(hashes[0]), [0;32], crate::expanded_mpt_capacity::max_proof_nodes() as Field, nodes,lengths,kinds,lists,items,compacts,ref_layouts,refs,ref_lengths,ref_kinds,terminal,1);
}

#[test(should_fail)]
fn test_poseidon2_rejects_generated_node_length_over_capacity() { assert_node_length_capacity(crate::expanded_mpt_capacity::max_node_rlp_bytes() as Field + 1); }

#[test(should_fail)]
fn test_poseidon2_rejects_generated_total_proof_length_over_capacity() { assert_total_length_capacity(crate::expanded_mpt_capacity::max_total_proof_rlp_bytes() as Field + 1); }

#[test(should_fail)]
fn test_poseidon2_wrong_hashed_child_identity_fails() {
    let (branch, leaf, _) = poseidon_branch_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = branch; nodes[1] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 50; lengths[1] = 35;
    let mut kinds = [0; 16]; kinds[0] = 0; kinds[1] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 50, 1, 49]; lists[1] = [0, 35, 1, 34];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16]; items[0][0] = [1, 33, 2, 32];
    for i in 1..17 { items[0][i] = [(33 + i) as Field, 1, (34 + i) as Field, 0]; }
    items[1][0] = [1, 33, 2, 32]; items[1][1] = [34, 1, 34, 1];
    let mut compacts = [[0; 4]; 16]; compacts[1] = items[1][0];
    let mut refs = [[0; 32]; 16]; refs[0][0] = 1;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 32;
    let mut ref_kinds = [0; 16]; ref_kinds[0] = 2;
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][0];
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, [0; 32], 1, [0; 32], 2, nodes, lengths, kinds, lists, items, compacts, ref_layouts, refs, ref_lengths, ref_kinds, terminal, 1);
}

#[test(should_fail)]
fn test_poseidon2_nonzero_inactive_padding_fails() {
    let (node, list, compact, value) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node; nodes[4][0] = 1;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    let root = [0x2f,0x68,0x6c,0x8f,0xbf,0x8a,0x4d,0x52,0x7d,0x03,0x42,0xe9,0x62,0x77,0x56,0x97,0x15,0xf9,0x4d,0x7e,0x0c,0x87,0xd6,0xff,0x1d,0xcf,0xd4,0xe9,0x7f,0x59,0x37,0x94];
    assert_inclusion(1, root, crate::hash_poseidon2::bytes32_to_field(root), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_poseidon2_rejects_wrong_root() {
    let (node, list, compact, value) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, [0; 32], 0, [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_poseidon2_rejects_malformed_compact_flags() {
    let (mut node, list, compact, value) = root_leaf_fixture(); node[2] = 0x40;
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, [0; 32], 1, [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_poseidon2_rejects_extra_active_node() {
    let (node, list, compact, value) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2; kinds[1] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    let root = [0x2f,0x68,0x6c,0x8f,0xbf,0x8a,0x4d,0x52,0x7d,0x03,0x42,0xe9,0x62,0x77,0x56,0x97,0x15,0xf9,0x4d,0x7e,0x0c,0x87,0xd6,0xff,0x1d,0xcf,0xd4,0xe9,0x7f,0x59,0x37,0x94];
    assert_inclusion(1, root, crate::hash_poseidon2::bytes32_to_field(root), [0; 32], 2, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_poseidon2_rejects_nonzero_inactive_metadata() {
    let (node, list, compact, value) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36; lengths[3] = 1;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    let root = [0x2f,0x68,0x6c,0x8f,0xbf,0x8a,0x4d,0x52,0x7d,0x03,0x42,0xe9,0x62,0x77,0x56,0x97,0x15,0xf9,0x4d,0x7e,0x0c,0x87,0xd6,0xff,0x1d,0xcf,0xd4,0xe9,0x7f,0x59,0x37,0x94];
    assert_inclusion(1, root, crate::hash_poseidon2::bytes32_to_field(root), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_poseidon2_rejects_terminal_value_over_capacity() {
    let (node, list, compact, value) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    let root = [0x2f,0x68,0x6c,0x8f,0xbf,0x8a,0x4d,0x52,0x7d,0x03,0x42,0xe9,0x62,0x77,0x56,0x97,0x15,0xf9,0x4d,0x7e,0x0c,0x87,0xd6,0xff,0x1d,0xcf,0xd4,0xe9,0x7f,0x59,0x37,0x94];
    assert_inclusion(1, root, crate::hash_poseidon2::bytes32_to_field(root), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 257);
}

fn assert_poseidon2_inline_reference_negative(ref_byte: u8, ref_kind: Field, ref_len: Field) {
    let mut leaf=[0;1024]; leaf[0]=0xc2; leaf[1]=0x20; leaf[2]=0x78;
    let mut extension=[0;1024]; extension[0]=0xe6; extension[1]=0xa1; extension[2]=0x00; for i in 0..32 { extension[3+i]=0; } extension[35]=0x83; extension[36]=0xc2; extension[37]=0x20; extension[38]=0x78;
    let mut nodes=[[0;1024];16]; nodes[0]=extension; nodes[1]=leaf; let mut lengths=[0;16]; lengths[0]=39; lengths[1]=3; let mut kinds=[0;16]; kinds[0]=1; kinds[1]=2;
    let mut lists=[[0;4];16]; lists[0]=[0,39,1,38]; lists[1]=[0,3,1,2]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[1,34,2,33]; items[0][1]=[35,4,36,3]; items[1][0]=[1,1,1,1]; items[1][1]=[2,1,2,1]; let mut compacts=[[0;4];16]; compacts[0]=items[0][0]; compacts[1]=items[1][0]; let mut layouts: [[Field;4];16]=[[0;4];16]; layouts[0]=items[0][1]; let mut refs=[[0;32];16]; refs[0][0]=ref_byte; refs[0][1]=0x20; refs[0][2]=0x78; let mut ref_lengths=[0;16]; ref_lengths[0]=ref_len; let mut ref_kinds=[0;16]; ref_kinds[0]=ref_kind; let mut terminal=[0;256]; terminal[0]=0x78;
    let root=[0x01,0x7c,0xf4,0x03,0x8d,0x95,0xbe,0xf0,0xea,0xb9,0x2d,0x92,0x00,0x50,0x1f,0x13,0x11,0x83,0x80,0x8b,0xa5,0xd8,0x95,0x4a,0xb0,0x39,0xe5,0xa2,0xd8,0xc8,0x7e,0x13];
    assert_inclusion(1, root, crate::hash_poseidon2::bytes32_to_field(root), [0;32], 2, nodes,lengths,kinds,lists,items,compacts,layouts,refs,ref_lengths,ref_kinds,terminal,1);
}

#[test(should_fail)]
fn test_poseidon2_rejects_wrong_inline_child_bytes() { assert_poseidon2_inline_reference_negative(0xc3,1,3); }

#[test(should_fail)]
fn test_poseidon2_rejects_noncanonical_child_reference_representation() { assert_poseidon2_inline_reference_negative(0xc2,2,3); }

#[test(should_fail)]
fn test_poseidon2_rejects_zero_length_extension_fragment() { assert_poseidon2_inline_reference_negative(0xc2,1,0); }

#[test(should_fail)]
fn test_poseidon2_rejects_nonzero_bytes_outside_declared_node_length() { let (mut node,list,compact,value)=root_leaf_fixture(); node[100]=1; assert_poseidon2_root_leaf_negative(node,list,compact,value,[0;32],36,2,1,1); }

#[test(should_fail)]
fn test_poseidon2_rejects_total_declared_active_bytes_over_capacity() { assert_total_length_capacity(crate::expanded_mpt_capacity::max_total_proof_rlp_bytes() as Field + 1); }

#[test(should_fail)]
fn test_poseidon2_root_bytes_field_bridge_mismatch() { let (node,list,compact,value)=root_leaf_fixture(); assert_poseidon2_root_leaf_negative(node,list,compact,value,[0;32],36,2,1,1); }

fn assert_poseidon2_root_leaf_negative(node: [u8;1024], list: [Field;4], compact: [Field;4], value: [Field;4], key: [u8;32], node_len: Field, kind: Field, count: Field, terminal_len: Field) {
    let mut nodes=[[0;1024];16]; nodes[0]=node; let mut lengths=[0;16]; lengths[0]=node_len; let mut kinds=[0;16]; kinds[0]=kind; let mut lists=[[0;4];16]; lists[0]=list; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=compact; items[0][1]=value; let mut compacts=[[0;4];16]; compacts[0]=compact; let mut terminal=[0;256]; terminal[0]=0x78; let root=crate::hash_poseidon2::hash_node(node,node_len);
    assert_inclusion(1, [0;32], root, key, count, nodes,lengths,kinds,lists,items,compacts,[[0;4];16],[[0;32];16],[0;16],[0;16],terminal,terminal_len);
}

fn assert_poseidon2_path_consumption_bound(cursor: Field, path_len: Field) {
    let c = as_u32(cursor); let p = as_u32(path_len);
    assert(c <= 64); assert(p <= 64); assert(c + p <= 64);
}

#[test(should_fail)]
fn test_poseidon2_rejects_malformed_branch_arity() { let (mut node,list,compact,value)=root_leaf_fixture(); node[0]=0xf0; assert_poseidon2_root_leaf_negative(node,list,compact,value,[0;32],36,0,1,1); }

#[test(should_fail)]
fn test_poseidon2_rejects_explicit_path_underconsumption() { let (node,list,compact,value)=root_leaf_fixture(); let mut key=[0;32]; key[31]=1; assert_poseidon2_root_leaf_negative(node,list,compact,value,key,36,2,1,1); }

#[test(should_fail)]
fn test_poseidon2_rejects_explicit_path_overconsumption() { assert_poseidon2_path_consumption_bound(0,65); }

#[test(should_fail)]
fn test_poseidon2_rejects_empty_selected_branch_child() { let (branch,leaf,_) = poseidon_branch_leaf_fixture(); let mut nodes=[[0;1024];16]; nodes[0]=branch; nodes[1]=leaf; let mut lengths=[0;16]; lengths[0]=50; lengths[1]=35; let mut kinds=[0;16]; kinds[0]=0; kinds[1]=2; let mut lists=[[0;4];16]; lists[0]=[0,50,1,49]; lists[1]=[0,35,1,34]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[1,33,2,32]; for i in 1..17 { items[0][i]=[(33+i) as Field,1,(34+i) as Field,0]; } items[1][0]=[1,33,2,32]; items[1][1]=[34,1,34,1]; let mut compacts=[[0;4];16]; compacts[1]=items[1][0]; let mut terminal=[0;256]; terminal[0]=0x78; let root=[0x1f,0xfb,0xfb,0x38,0x36,0x38,0x6f,0xd7,0x87,0x0c,0x00,0x3f,0x58,0xdb,0xfa,0x4c,0xba,0x59,0xa6,0x73,0x5e,0x47,0xbe,0x71,0x35,0xeb,0x2b,0x11,0x50,0x10,0x6c,0x5f]; assert_inclusion(1,root,crate::hash_poseidon2::bytes32_to_field(root),[0;32],2,nodes,lengths,kinds,lists,items,compacts,[[0;4];16],[[0;32];16],[0;16],[0;16],terminal,1); }

#[test(should_fail)]
fn test_poseidon2_rejects_empty_branch_terminal_value() { let (branch,_,_) = poseidon_branch_leaf_fixture(); let mut nodes=[[0;1024];16]; nodes[0]=branch; let mut lengths=[0;16]; lengths[0]=50; let mut kinds=[0;16]; kinds[0]=0; let mut lists=[[0;4];16]; lists[0]=[0,50,1,49]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[1,33,2,32]; for i in 1..17 { items[0][i]=[(33+i) as Field,1,(34+i) as Field,0]; } let mut terminal=[0;256]; terminal[0]=0x78; let root=[0x1f,0xfb,0xfb,0x38,0x36,0x38,0x6f,0xd7,0x87,0x0c,0x00,0x3f,0x58,0xdb,0xfa,0x4c,0xba,0x59,0xa6,0x73,0x5e,0x47,0xbe,0x71,0x35,0xeb,0x2b,0x11,0x50,0x10,0x6c,0x5f]; assert_inclusion(1,root,crate::hash_poseidon2::bytes32_to_field(root),[0;32],1,nodes,lengths,kinds,lists,items,[[0;4];16],[[0;4];16],[[0;32];16],[0;16],[0;16],terminal,1); }
