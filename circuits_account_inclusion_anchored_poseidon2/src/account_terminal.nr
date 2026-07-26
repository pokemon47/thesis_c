fn as_u32(value: Field) -> u32 {
    let converted = value as u32;
    assert(value == converted as Field);
    converted
}

fn byte_at(input: [u8; 256], index: Field) -> u8 {
    let idx = as_u32(index);
    assert(idx < 256);
    input[idx]
}

fn parse_list_prefix(input: [u8; 256], terminal_value_len: Field) -> (Field, Field) {
    let len_u32 = as_u32(terminal_value_len);
    assert(len_u32 > 0);
    assert(len_u32 <= 256);

    let prefix = byte_at(input, 0) as u32;
    if prefix < 0xf8 {
        assert(prefix >= 0xc0);
        let payload_len = prefix - 0xc0;
        assert(len_u32 == 1 + payload_len);
        (1, payload_len as Field)
    } else {
        let lol = prefix - 0xf7;
        assert(lol >= 1);
        assert(lol <= 2);
        let payload_len = if lol == 1 {
            let first = byte_at(input, 1) as u32;
            assert(first != 0);
            first
        } else {
            let hi = byte_at(input, 1) as u32;
            let lo = byte_at(input, 2) as u32;
            assert(hi != 0);
            hi * 256 + lo
        };
        assert(payload_len > 55);
        assert(len_u32 == 1 + lol + payload_len);
        ((1 + lol) as Field, payload_len as Field)
    }
}

fn parse_scalar_item(
    input: [u8; 256],
    offset: Field,
    terminal_value_len: Field,
) -> ([u8; 32], Field) {
    let offset_u32 = as_u32(offset);
    let limit_u32 = as_u32(terminal_value_len);
    assert(offset_u32 < limit_u32);

    let prefix = byte_at(input, offset) as u32;
    let mut out = [0; 32];
    if prefix < 0x80 {
        assert(prefix > 0);
        out[31] = prefix as u8;
        assert(offset_u32 + 1 <= limit_u32);
        (out, offset + 1)
    } else if prefix == 0x80 {
        assert(offset_u32 + 1 <= limit_u32);
        (out, offset + 1)
    } else {
        assert(prefix <= 0xb7);
        let payload_len = prefix - 0x80;
        assert(payload_len > 0);
        assert(payload_len <= 32);
        assert(offset_u32 + 1 + payload_len <= limit_u32);
        if payload_len == 1 {
            assert(byte_at(input, offset + 1) >= 0x80);
        }
        for i in 0..32 {
            if i < payload_len {
                out[32 - payload_len + i] = byte_at(input, offset + 1 + i as Field);
            }
        }
        (out, offset + 1 + payload_len as Field)
    }
}

fn parse_bytes32_item(
    input: [u8; 256],
    offset: Field,
    terminal_value_len: Field,
) -> ([u8; 32], Field) {
    let offset_u32 = as_u32(offset);
    let limit_u32 = as_u32(terminal_value_len);
    assert(offset_u32 + 33 <= limit_u32);

    let prefix = byte_at(input, offset);
    assert(prefix == 0xA0);
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = byte_at(input, offset + 1 + i as Field);
    }
    (out, offset + 33)
}

pub fn assert_canonical_terminal_account_rlp(
    terminal_value: [u8; 256],
    terminal_value_len: Field,
) {
    let (payload_offset, payload_len) = parse_list_prefix(terminal_value, terminal_value_len);
    let mut cursor = payload_offset;
    let (_, next_cursor) = parse_scalar_item(terminal_value, cursor, terminal_value_len);
    cursor = next_cursor;
    let (_, next_cursor) = parse_scalar_item(terminal_value, cursor, terminal_value_len);
    cursor = next_cursor;
    let (_, next_cursor) = parse_bytes32_item(terminal_value, cursor, terminal_value_len);
    cursor = next_cursor;
    let (_, next_cursor) = parse_bytes32_item(terminal_value, cursor, terminal_value_len);
    cursor = next_cursor;

    assert(as_u32(cursor) == as_u32(payload_offset) + as_u32(payload_len));
    assert(as_u32(payload_offset) + as_u32(payload_len) == as_u32(terminal_value_len));
}
