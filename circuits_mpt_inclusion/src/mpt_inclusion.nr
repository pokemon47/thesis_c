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
    assert(crate::hash_keccak::hash_node(node_bytes[0], node_lengths[0]) == public_state_root);

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
                    assert(crate::hash_keccak::hash_node(node_bytes[i + 1], node_lengths[i + 1]) == selected_ref_bytes[i]);
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

fn root_leaf_fixture() -> ([u8; 1024], [Field; 4], [Field; 4], [Field; 4], [Field; 4]) {
    let mut node = [0; 1024];
    node[0] = 0xe3;
    node[1] = 0xa1;
    node[2] = 0x20;
    node[35] = 0x78;
    (
        node,
        [0, 36, 1, 35],
        [1, 34, 2, 33],
        [35, 1, 35, 1],
        [0, 0, 0, 0],
    )
}

#[test]
fn test_root_leaf_inclusion_uses_authenticated_value() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16];
    nodes[0] = node;
    let mut lengths = [0; 16];
    lengths[0] = 36;
    let mut kinds = [0; 16];
    kinds[0] = 2;
    let mut lists = [[0; 4]; 16];
    lists[0] = list;
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = compact;
    items[0][1] = value;
    let mut compacts = [[0; 4]; 16];
    compacts[0] = compact;
    let mut terminal = [0; 256];
    terminal[0] = 0x78;
    assert_inclusion(
        1,
        crate::hash_keccak::hash_node(node, 36),
        [0; 32],
        1,
        nodes,
        lengths,
        kinds,
        lists,
        items,
        compacts,
        [[0; 4]; 16],
        [[0; 32]; 16],
        [0; 16],
        [0; 16],
        terminal,
        1,
    );
}

#[test(should_fail)]
fn test_root_leaf_wrong_terminal_buffer_fails() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x79;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

fn branch_leaf_fixture() -> ([u8; 1024], [u8; 1024]) {
    let mut leaf = [0; 1024];
    leaf[0] = 0xe2;
    leaf[1] = 0xa0;
    leaf[2] = 0x30;
    leaf[34] = 0x78;

    let leaf_hash = crate::hash_keccak::hash_node(leaf, 35);
    let mut branch = [0; 1024];
    branch[0] = 0xf1;
    branch[1] = 0xa0;
    for i in 0..32 { branch[2 + i] = leaf_hash[i]; }
    for i in 0..16 { branch[34 + i] = 0x80; }
    (branch, leaf)
}

#[test]
fn test_hashed_branch_to_leaf_inclusion() {
    let (branch, leaf) = branch_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = branch; nodes[1] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 50; lengths[1] = 35;
    let mut kinds = [0; 16]; kinds[0] = 0; kinds[1] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 50, 1, 49]; lists[1] = [0, 35, 1, 34];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = [1, 33, 2, 32];
    for i in 1..17 { items[0][i] = [(33 + i) as Field, 1, (34 + i) as Field, 0]; }
    items[1][0] = [1, 33, 2, 32]; items[1][1] = [34, 1, 34, 1];
    let mut compacts = [[0; 4]; 16]; compacts[1] = [1, 33, 2, 32];
    let mut refs = [[0; 32]; 16];
    let leaf_hash = crate::hash_keccak::hash_node(leaf, 35);
    refs[0] = leaf_hash;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 32;
    let mut ref_kinds = [0; 16]; ref_kinds[0] = 2;
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][0];
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(
        1, crate::hash_keccak::hash_node(branch, 50), [0; 32], 2,
        nodes, lengths, kinds, lists, items, compacts, ref_layouts, refs,
        ref_lengths, ref_kinds, terminal, 1,
    );
}

#[test]
fn test_max_shaped_canonical_branch_boundary_inclusion() {
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

    let final_branch_hash = crate::hash_keccak::hash_node(final_branch, final_branch_len);
    let mut root_extension = [0; 1024];
    root_extension[0] = 0xf8;
    root_extension[1] = 0x43;
    root_extension[2] = 0xa1;
    root_extension[3] = 0x00;
    for i in 0..32 { root_extension[4 + i] = 0x00; }
    root_extension[36] = 0xa0;
    for i in 0..32 { root_extension[37 + i] = final_branch_hash[i]; }

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
    refs[0] = final_branch_hash;
    let mut ref_lengths: [Field; 16] = [0; 16];
    ref_lengths[0] = 32;
    let mut ref_kinds: [Field; 16] = [0; 16];
    ref_kinds[0] = 2;
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16];
    ref_layouts[0] = items[0][1];
    assert(as_u32(final_branch_len) == 790);
    assert(as_u32(final_branch_len) == crate::expanded_mpt_capacity::max_node_rlp_bytes() - 234);
    let root = crate::hash_keccak::hash_node(root_extension, lengths[0]);
    assert_inclusion(
        1,
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
        terminal_value_len,
    );
}

#[test]
fn test_extension_to_inline_leaf_inclusion() {
    let mut leaf = [0; 1024];
    leaf[0] = 0xc2; leaf[1] = 0x20; leaf[2] = 0x78;
    let mut extension = [0; 1024];
    extension[0] = 0xe6; extension[1] = 0xa1; extension[2] = 0x00;
    for i in 0..32 { extension[3 + i] = 0; }
    extension[35] = 0x83; extension[36] = 0xc2; extension[37] = 0x20; extension[38] = 0x78;

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
    assert_inclusion(
        1, crate::hash_keccak::hash_node(extension, 39), [0; 32], 2,
        nodes, lengths, kinds, lists, items, compacts, ref_layouts, ref_bytes,
        ref_lengths, ref_kinds, terminal, 1,
    );
}

#[test]
fn test_extension_to_branch_value_terminal_inclusion() {
    let mut branch = [0; 1024]; branch[0] = 0xd1;
    for i in 0..16 { branch[1 + i] = 0x80; }
    branch[17] = 0x78;
    let mut extension = [0; 1024]; extension[0] = 0xf5; extension[1] = 0xa1; extension[2] = 0x00;
    for i in 0..32 { extension[3 + i] = 0; }
    extension[35] = 0x92; extension[36] = 0xd1;
    for i in 0..16 { extension[37 + i] = 0x80; }
    extension[53] = 0x78;
    let mut nodes = [[0; 1024]; 16]; nodes[0] = extension; nodes[1] = branch;
    let mut lengths = [0; 16]; lengths[0] = 54; lengths[1] = 18;
    let mut kinds = [0; 16]; kinds[0] = 1; kinds[1] = 0;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 54, 1, 53]; lists[1] = [0, 18, 1, 17];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = [1, 34, 2, 33]; items[0][1] = [35, 19, 36, 18];
    for i in 0..16 { items[1][i] = [(1 + i) as Field, 1, (2 + i) as Field, 0]; }
    items[1][16] = [17, 1, 17, 1];
    let mut compacts = [[0; 4]; 16]; compacts[0] = items[0][0];
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][1];
    let mut ref_bytes = [[0; 32]; 16]; ref_bytes[0][0] = 0xd1;
    for i in 0..16 { ref_bytes[0][1 + i] = 0x80; }
    ref_bytes[0][17] = 0x78;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 18;
    let mut ref_kinds = [0; 16]; ref_kinds[0] = 1;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(extension, 54), [0; 32], 2, nodes, lengths, kinds, lists, items, compacts, ref_layouts, ref_bytes, ref_lengths, ref_kinds, terminal, 1);
}

#[test]
fn test_branch_to_extension_to_inline_leaf_inclusion() {
    let mut leaf = [0; 1024]; leaf[0] = 0xc2; leaf[1] = 0x20; leaf[2] = 0x78;
    let mut extension = [0; 1024]; extension[0] = 0xe5; extension[1] = 0xa0; extension[2] = 0x10;
    for i in 0..31 { extension[3 + i] = 0; }
    extension[34] = 0x83; extension[35] = 0xc2; extension[36] = 0x20; extension[37] = 0x78;
    let extension_hash = crate::hash_keccak::hash_node(extension, 38);
    let mut branch = [0; 1024]; branch[0] = 0xf1; branch[1] = 0xa0;
    for i in 0..32 { branch[2 + i] = extension_hash[i]; }
    for i in 0..16 { branch[34 + i] = 0x80; }
    let mut nodes = [[0; 1024]; 16]; nodes[0] = branch; nodes[1] = extension; nodes[2] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 50; lengths[1] = 38; lengths[2] = 3;
    let mut kinds = [0; 16]; kinds[0] = 0; kinds[1] = 1; kinds[2] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 50, 1, 49]; lists[1] = [0, 38, 1, 37]; lists[2] = [0, 3, 1, 2];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16];
    items[0][0] = [1, 33, 2, 32];
    for i in 1..17 { items[0][i] = [(33 + i) as Field, 1, (34 + i) as Field, 0]; }
    items[1][0] = [1, 33, 2, 32]; items[1][1] = [34, 4, 35, 3];
    items[2][0] = [1, 1, 1, 1]; items[2][1] = [2, 1, 2, 1];
    let mut compacts = [[0; 4]; 16]; compacts[1] = items[1][0]; compacts[2] = items[2][0];
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][0]; ref_layouts[1] = items[1][1];
    let mut ref_bytes = [[0; 32]; 16]; ref_bytes[0] = extension_hash; ref_bytes[1][0] = 0xc2; ref_bytes[1][1] = 0x20; ref_bytes[1][2] = 0x78;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 32; ref_lengths[1] = 3;
    let mut ref_kinds = [0; 16]; ref_kinds[0] = 2; ref_kinds[1] = 1;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(branch, 50), [0; 32], 3, nodes, lengths, kinds, lists, items, compacts, ref_layouts, ref_bytes, ref_lengths, ref_kinds, terminal, 1);
}

#[test]
fn test_mixed_hashed_then_inline_transitions() {
    let mut leaf = [0; 1024]; leaf[0] = 0xc2; leaf[1] = 0x20; leaf[2] = 0x78;
    let mut extension = [0; 1024]; extension[0] = 0xe5; extension[1] = 0xa0; extension[2] = 0x10;
    for i in 0..31 { extension[3 + i] = 0; }
    extension[34] = 0x83; extension[35] = 0xc2; extension[36] = 0x20; extension[37] = 0x78;
    let extension_hash = crate::hash_keccak::hash_node(extension, 38);
    let mut branch = [0; 1024]; branch[0] = 0xf1; branch[1] = 0xa0;
    for i in 0..32 { branch[2 + i] = extension_hash[i]; }
    for i in 0..16 { branch[34 + i] = 0x80; }
    let mut nodes = [[0; 1024]; 16]; nodes[0] = branch; nodes[1] = extension; nodes[2] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 50; lengths[1] = 38; lengths[2] = 3;
    let mut kinds = [0; 16]; kinds[0] = 0; kinds[1] = 1; kinds[2] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 50, 1, 49]; lists[1] = [0, 38, 1, 37]; lists[2] = [0, 3, 1, 2];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16]; items[0][0] = [1, 33, 2, 32];
    for i in 1..17 { items[0][i] = [(33 + i) as Field, 1, (34 + i) as Field, 0]; }
    items[1][0] = [1, 33, 2, 32]; items[1][1] = [34, 4, 35, 3]; items[2][0] = [1, 1, 1, 1]; items[2][1] = [2, 1, 2, 1];
    let mut compacts = [[0; 4]; 16]; compacts[1] = items[1][0]; compacts[2] = items[2][0];
    let mut ref_layouts: [[Field; 4]; 16] = [[0; 4]; 16]; ref_layouts[0] = items[0][0]; ref_layouts[1] = items[1][1];
    let mut ref_bytes = [[0; 32]; 16]; ref_bytes[0] = extension_hash; ref_bytes[1][0] = 0xc2; ref_bytes[1][1] = 0x20; ref_bytes[1][2] = 0x78;
    let mut ref_lengths = [0; 16]; ref_lengths[0] = 32; ref_lengths[1] = 3; let mut ref_kinds = [0; 16]; ref_kinds[0] = 2; ref_kinds[1] = 1;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(branch, 50), [0; 32], 3, nodes, lengths, kinds, lists, items, compacts, ref_layouts, ref_bytes, ref_lengths, ref_kinds, terminal, 1);
}

#[test]
fn test_terminal_value_near_generated_capacity() {
    let value_len = crate::expanded_mpt_capacity::max_terminal_value_bytes() - 1;
    let mut node = [0; 1024]; node[0] = 0xf9; node[1] = 0x01; node[2] = 0x23; node[3] = 0xa1; node[4] = 0x20;
    for i in 0..255 { node[39 + i] = (i as u8) + 1; }
    node[37] = 0xb8; node[38] = 0xff;
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 294;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0, 294, 3, 291];
    let mut items: [[[Field; 4]; 17]; 16] = [[[0; 4]; 17]; 16]; items[0][0] = [3,34,4,33]; items[0][1] = [37,257,39,255];
    let mut compacts = [[0;4];16]; compacts[0] = items[0][0]; let mut terminal=[0;256];
    for i in 0..255 { terminal[i] = (i as u8) + 1; }
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 294), [0;32], 1, nodes, lengths, kinds, lists, items, compacts, [[0;4];16], [[0;32];16], [0;16], [0;16], terminal, value_len as Field);
}

fn assert_node_length_capacity(length: Field) { assert(as_u32(length) <= crate::expanded_mpt_capacity::max_node_rlp_bytes()); }
fn assert_total_length_capacity(length: Field) { assert(as_u32(length) <= crate::expanded_mpt_capacity::max_total_proof_rlp_bytes()); }

#[test]
fn test_multiple_extensions_separated_by_branch() {
    let mut leaf=[0;1024]; leaf[0]=0xdd; leaf[1]=0x9b; leaf[2]=0x20; for i in 0..26 { leaf[3+i]=0; } leaf[29]=0x78;
    let mut extension2=[0;1024]; extension2[0]=0xe6; extension2[1]=0x86; extension2[2]=0x00; for i in 0..5 { extension2[3+i]=0; } extension2[8]=0x9e; for i in 0..30 { extension2[9+i]=leaf[i]; }
    let ext2_hash=crate::hash_keccak::hash_node(extension2,39); let mut branch=[0;1024]; branch[0]=0xf1; branch[1]=0xa0; for i in 0..32 { branch[2+i]=ext2_hash[i]; } for i in 0..16 { branch[34+i]=0x80; }
    let branch_hash=crate::hash_keccak::hash_node(branch,50); let mut extension1=[0;1024]; extension1[0]=0xe2; extension1[1]=0x10; extension1[2]=0xa0; for i in 0..32 { extension1[3+i]=branch_hash[i]; }
    let mut nodes=[[0;1024];16]; nodes[0]=extension1; nodes[1]=branch; nodes[2]=extension2; nodes[3]=leaf; let mut lengths=[0;16]; lengths[0]=35; lengths[1]=50; lengths[2]=39; lengths[3]=30; let mut kinds=[0;16]; kinds[0]=1; kinds[1]=0; kinds[2]=1; kinds[3]=2;
    let mut lists=[[0;4];16]; lists[0]=[0,35,1,34]; lists[1]=[0,50,1,49]; lists[2]=[0,39,1,38]; lists[3]=[0,30,1,29]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[1,1,1,1]; items[0][1]=[2,33,3,32]; items[1][0]=[1,33,2,32]; for i in 1..17 { items[1][i]=[(33+i) as Field,1,(34+i) as Field,0]; } items[2][0]=[1,7,2,6]; items[2][1]=[8,31,9,30]; items[3][0]=[1,28,2,27]; items[3][1]=[29,1,29,1];
    let mut compacts=[[0;4];16]; compacts[0]=items[0][0]; compacts[2]=items[2][0]; compacts[3]=items[3][0]; let mut ref_layouts: [[Field;4];16]=[[0;4];16]; ref_layouts[0]=items[0][1]; ref_layouts[1]=items[1][0]; ref_layouts[2]=items[2][1]; let mut refs=[[0;32];16]; refs[0]=branch_hash; refs[1]=ext2_hash; for i in 0..30 { refs[2][i]=leaf[i]; } let mut ref_lengths=[0;16]; ref_lengths[0]=32; ref_lengths[1]=32; ref_lengths[2]=30; let mut ref_kinds=[0;16]; ref_kinds[0]=2; ref_kinds[1]=2; ref_kinds[2]=1; let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(extension1,35), [0;32], 4, nodes,lengths,kinds,lists,items,compacts,ref_layouts,refs,ref_lengths,ref_kinds,terminal,1);
}

#[test]
fn test_maximum_active_branch_chain_with_zero_padding() {
    let mut leaf=[0;1024]; leaf[0]=0xdb; leaf[1]=0x99; leaf[2]=0x30; for i in 0..24 { leaf[3+i]=0; } leaf[27]=0x78;
    let mut nodes=[[0;1024];16]; nodes[15]=leaf; let mut lengths=[0;16]; lengths[15]=28; let mut kinds=[0;16]; kinds[15]=2;
    for k in 0..15 { let idx=14-k; let mut branch=[0;1024]; if idx==14 { branch[0]=0xed; branch[1]=0x9c; for j in 0..28 { branch[2+j]=nodes[15][j]; } for j in 0..16 { branch[30+j]=0x80; } lengths[idx]=46; } else { branch[0]=0xf1; branch[1]=0xa0; let child_hash=crate::hash_keccak::hash_node(nodes[idx+1], lengths[idx+1]); for j in 0..32 { branch[2+j]=child_hash[j]; } for j in 0..16 { branch[34+j]=0x80; } lengths[idx]=50; } nodes[idx]=branch; kinds[idx]=0; }
    let mut lists=[[0;4];16]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; let mut compacts=[[0;4];16]; let mut refs=[[0;32];16]; let mut ref_lengths=[0;16]; let mut ref_kinds=[0;16]; let mut ref_layouts: [[Field;4];16]=[[0;4];16];
    for i in 0..15 { lists[i]=[0,lengths[i],1,lengths[i]-1]; if i==14 { items[i][0]=[1,29,2,28]; ref_lengths[i]=28; ref_kinds[i]=1; for j in 0..28 { refs[i][j]=nodes[15][j]; } } else { items[i][0]=[1,33,2,32]; ref_lengths[i]=32; ref_kinds[i]=2; refs[i]=crate::hash_keccak::hash_node(nodes[i+1], lengths[i+1]); } ref_layouts[i]=items[i][0]; let empty_start=if i==14 {30} else {34}; for j in 1..17 { items[i][j]=[(empty_start+j-1) as Field,1,(empty_start+j) as Field,0]; } }
    lists[15]=[0,28,1,27]; items[15][0]=[1,26,2,25]; items[15][1]=[27,1,27,1]; compacts[15]=items[15][0]; let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(nodes[0], lengths[0]), [0;32], crate::expanded_mpt_capacity::max_proof_nodes() as Field, nodes,lengths,kinds,lists,items,compacts,ref_layouts,refs,ref_lengths,ref_kinds,terminal,1);
}

#[test(should_fail)]
fn test_rejects_generated_node_length_over_capacity() { assert_node_length_capacity(crate::expanded_mpt_capacity::max_node_rlp_bytes() as Field + 1); }

#[test(should_fail)]
fn test_rejects_generated_total_proof_length_over_capacity() { assert_total_length_capacity(crate::expanded_mpt_capacity::max_total_proof_rlp_bytes() as Field + 1); }

#[test(should_fail)]
fn test_rejects_wrong_witness_version() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(2, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_nonzero_inactive_padding() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node; nodes[3][0] = 1;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_compact_path_mismatch() {
    let (mut node, list, compact, value, _) = root_leaf_fixture();
    node[2] = 0x21;
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_wrong_root() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, [0; 32], [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_malformed_compact_flags() {
    let (mut node, list, compact, value, _) = root_leaf_fixture(); node[2] = 0x40;
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_malformed_two_item_node() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 1;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_extra_active_node() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2; kinds[1] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 2, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_nonzero_inactive_metadata() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36; lengths[3] = 1;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 1);
}

#[test(should_fail)]
fn test_rejects_terminal_value_over_capacity() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = 36;
    let mut kinds = [0; 16]; kinds[0] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, 36), [0; 32], 1, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, 257);
}

fn assert_root_leaf_negative(node: [u8; 1024], list: [Field; 4], compact: [Field; 4], value: [Field; 4], key: [u8; 32], node_len: Field, kind: Field, count: Field, terminal_len: Field) {
    let mut nodes = [[0; 1024]; 16]; nodes[0] = node;
    let mut lengths = [0; 16]; lengths[0] = node_len;
    let mut kinds = [0; 16]; kinds[0] = kind;
    let mut lists = [[0; 4]; 16]; lists[0] = list;
    let mut items = [[[0; 4]; 17]; 16]; items[0][0] = compact; items[0][1] = value;
    let mut compacts = [[0; 4]; 16]; compacts[0] = compact;
    let mut terminal = [0; 256]; terminal[0] = 0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(node, node_len), key, count, nodes, lengths, kinds, lists, items, compacts, [[0; 4]; 16], [[0; 32]; 16], [0; 16], [0; 16], terminal, terminal_len);
}

fn assert_path_consumption_bound(cursor: Field, path_len: Field) {
    let c = as_u32(cursor); let p = as_u32(path_len);
    assert(c <= 64); assert(p <= 64); assert(c + p <= 64);
}

#[test(should_fail)]
fn test_rejects_malformed_branch_arity() {
    let (mut node, list, compact, value, _) = root_leaf_fixture(); node[0] = 0xf0;
    assert_root_leaf_negative(node, list, compact, value, [0; 32], 36, 0, 1, 1);
}

#[test(should_fail)]
fn test_rejects_explicit_path_underconsumption() {
    let (node, list, compact, value, _) = root_leaf_fixture();
    let mut key = [0; 32]; key[31] = 1;
    assert_root_leaf_negative(node, list, compact, value, key, 36, 2, 1, 1);
}

#[test(should_fail)]
fn test_rejects_explicit_path_overconsumption() {
    assert_path_consumption_bound(0, 65);
}

#[test(should_fail)]
fn test_rejects_empty_selected_branch_child() {
    let (branch, leaf) = branch_leaf_fixture();
    let mut nodes = [[0; 1024]; 16]; nodes[0] = branch; nodes[1] = leaf;
    let mut lengths = [0; 16]; lengths[0] = 50; lengths[1] = 35;
    let mut kinds = [0; 16]; kinds[0] = 0; kinds[1] = 2;
    let mut lists = [[0; 4]; 16]; lists[0] = [0,50,1,49]; lists[1] = [0,35,1,34];
    let mut items = [[[0;4];17];16]; items[0][0]=[1,33,2,32]; for i in 1..17 { items[0][i]=[(33+i) as Field,1,(34+i) as Field,0]; } items[1][0]=[1,33,2,32]; items[1][1]=[34,1,34,1];
    let mut compacts=[[0;4];16]; compacts[1]=items[1][0]; let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(branch,50), [0;32], 2, nodes,lengths,kinds,lists,items,compacts,[[0;4];16],[[0;32];16],[0;16],[0;16],terminal,1);
}

#[test(should_fail)]
fn test_rejects_empty_branch_terminal_value() {
    let (branch, _) = branch_leaf_fixture();
    let mut nodes=[[0;1024];16]; nodes[0]=branch; let mut lengths=[0;16]; lengths[0]=50; let mut kinds=[0;16]; kinds[0]=0;
    let mut lists=[[0;4];16]; lists[0]=[0,50,1,49]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[1,33,2,32]; for i in 1..17 { items[0][i]=[(33+i) as Field,1,(34+i) as Field,0]; } let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(branch,50), [0;32], 1, nodes,lengths,kinds,lists,items,[[0;4];16],[[0;4];16],[[0;32];16],[0;16],[0;16],terminal,1);
}

fn assert_inline_reference_negative(ref_byte: u8, ref_kind: Field, ref_len: Field) {
    let mut leaf=[0;1024]; leaf[0]=0xc2; leaf[1]=0x20; leaf[2]=0x78;
    let mut extension=[0;1024]; extension[0]=0xe6; extension[1]=0xa1; extension[2]=0x00; for i in 0..32 { extension[3+i]=0; } extension[35]=0x83; extension[36]=0xc2; extension[37]=0x20; extension[38]=0x78;
    let mut nodes=[[0;1024];16]; nodes[0]=extension; nodes[1]=leaf; let mut lengths=[0;16]; lengths[0]=39; lengths[1]=3; let mut kinds=[0;16]; kinds[0]=1; kinds[1]=2;
    let mut lists=[[0;4];16]; lists[0]=[0,39,1,38]; lists[1]=[0,3,1,2]; let mut items: [[[Field;4];17];16]=[[[0;4];17];16]; items[0][0]=[1,34,2,33]; items[0][1]=[35,4,36,3]; items[1][0]=[1,1,1,1]; items[1][1]=[2,1,2,1]; let mut compacts=[[0;4];16]; compacts[0]=items[0][0]; compacts[1]=items[1][0]; let mut layouts: [[Field;4];16]=[[0;4];16]; layouts[0]=items[0][1]; let mut refs=[[0;32];16]; refs[0][0]=ref_byte; refs[0][1]=0x20; refs[0][2]=0x78; let mut ref_lengths=[0;16]; ref_lengths[0]=ref_len; let mut ref_kinds=[0;16]; ref_kinds[0]=ref_kind; let mut terminal=[0;256]; terminal[0]=0x78;
    assert_inclusion(1, crate::hash_keccak::hash_node(extension,39), [0;32], 2, nodes,lengths,kinds,lists,items,compacts,layouts,refs,ref_lengths,ref_kinds,terminal,1);
}

#[test(should_fail)]
fn test_rejects_wrong_inline_child_bytes() { assert_inline_reference_negative(0xc3, 1, 3); }

#[test(should_fail)]
fn test_rejects_noncanonical_child_reference_representation() { assert_inline_reference_negative(0xc2, 2, 3); }

#[test(should_fail)]
fn test_rejects_zero_length_extension_fragment() { assert_inline_reference_negative(0xc2, 1, 0); }

#[test(should_fail)]
fn test_rejects_nonzero_bytes_outside_declared_node_length() {
    let (mut node, list, compact, value, _) = root_leaf_fixture(); node[100] = 1;
    assert_root_leaf_negative(node, list, compact, value, [0;32], 36, 2, 1, 1);
}

#[test(should_fail)]
fn test_rejects_total_declared_active_bytes_over_capacity() { assert_total_length_capacity(crate::expanded_mpt_capacity::max_total_proof_rlp_bytes() as Field + 1); }
