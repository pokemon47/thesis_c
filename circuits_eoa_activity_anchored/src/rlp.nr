use crate::expanded_header_capacity::max_header_bytes;

pub struct RlpItemLayout {
    pub encoded_offset: u32,
    pub encoded_len: u32,
    pub payload_offset: u32,
    pub payload_len: u32,
    pub is_list: bool,
}

fn byte_at(input: [u8; 640], active_len: u32, index: u32) -> u8 {
    assert(index < active_len);
    assert(index < max_header_bytes());
    input[index]
}

fn assert_range(offset: u32, encoded_len: u32, active_len: u32) {
    assert(encoded_len > 0);
    assert(offset + encoded_len <= active_len);
}

fn parse_short_string(input: [u8; 640], active_len: u32, offset: u32, first: u32) -> RlpItemLayout {
    let payload_len = first - 0x80;
    let encoded_len = 1 + payload_len;
    assert_range(offset, encoded_len, active_len);
    if payload_len == 1 {
        assert(byte_at(input, active_len, offset + 1) >= 0x80);
    }
    RlpItemLayout {
        encoded_offset: offset,
        encoded_len,
        payload_offset: offset + 1,
        payload_len,
        is_list: false,
    }
}

fn parse_long_string(input: [u8; 640], active_len: u32, offset: u32, first: u32) -> RlpItemLayout {
    let len_of_len = first - 0xb7;
    assert(len_of_len <= 2);
    assert_range(offset, 1 + len_of_len, active_len);
    let payload_len = if len_of_len == 1 {
        let first_len_byte = byte_at(input, active_len, offset + 1) as u32;
        assert(first_len_byte != 0);
        first_len_byte
    } else {
        let hi = byte_at(input, active_len, offset + 1) as u32;
        let lo = byte_at(input, active_len, offset + 2) as u32;
        assert(hi != 0);
        hi * 256 + lo
    };
    assert(payload_len > 55);
    let encoded_len = 1 + len_of_len + payload_len;
    assert_range(offset, encoded_len, active_len);
    RlpItemLayout {
        encoded_offset: offset,
        encoded_len,
        payload_offset: offset + 1 + len_of_len,
        payload_len,
        is_list: false,
    }
}

fn parse_short_list(_input: [u8; 640], active_len: u32, offset: u32, first: u32) -> RlpItemLayout {
    let payload_len = first - 0xc0;
    let encoded_len = 1 + payload_len;
    assert_range(offset, encoded_len, active_len);
    RlpItemLayout {
        encoded_offset: offset,
        encoded_len,
        payload_offset: offset + 1,
        payload_len,
        is_list: true,
    }
}

fn parse_long_list(input: [u8; 640], active_len: u32, offset: u32, first: u32) -> RlpItemLayout {
    let len_of_len = first - 0xf7;
    assert(len_of_len <= 2);
    assert_range(offset, 1 + len_of_len, active_len);
    let payload_len = if len_of_len == 1 {
        let first_len_byte = byte_at(input, active_len, offset + 1) as u32;
        assert(first_len_byte != 0);
        first_len_byte
    } else {
        let hi = byte_at(input, active_len, offset + 1) as u32;
        let lo = byte_at(input, active_len, offset + 2) as u32;
        assert(hi != 0);
        hi * 256 + lo
    };
    assert(payload_len > 55);
    let encoded_len = 1 + len_of_len + payload_len;
    assert_range(offset, encoded_len, active_len);
    RlpItemLayout {
        encoded_offset: offset,
        encoded_len,
        payload_offset: offset + 1 + len_of_len,
        payload_len,
        is_list: true,
    }
}

pub fn parse_rlp_item(input: [u8; 640], active_len: u32, offset: u32) -> RlpItemLayout {
    assert(offset < active_len);
    let first = byte_at(input, active_len, offset) as u32;
    if first < 0x80 {
        RlpItemLayout {
            encoded_offset: offset,
            encoded_len: 1,
            payload_offset: offset,
            payload_len: 1,
            is_list: false,
        }
    } else if first <= 0xb7 {
        parse_short_string(input, active_len, offset, first)
    } else if first <= 0xbf {
        parse_long_string(input, active_len, offset, first)
    } else if first <= 0xf7 {
        parse_short_list(input, active_len, offset, first)
    } else {
        parse_long_list(input, active_len, offset, first)
    }
}

pub fn encoded_slice(input: [u8; 640], layout: RlpItemLayout) -> [u8; 640] {
    let mut out = [0; 640];
    for i in 0..640 {
        if i < layout.encoded_len {
            out[i] = input[layout.encoded_offset + i];
        }
    }
    out
}

pub fn payload_byte(input: [u8; 640], layout: RlpItemLayout, index: u32) -> u8 {
    assert(index < layout.payload_len);
    byte_at(input, layout.payload_offset + layout.payload_len, layout.payload_offset + index)
}
