const std = @import("std");

pub const Encoder = struct {
    const Self = @This();

    buffer: []const u8,
    index: ?usize,
    bit_off: u3,

    pub fn init(buffer: []const u8) Encoder {
        return .{
            .buffer = buffer,
            .index = 0,
            .bit_off = 0,
        };
    }

    pub fn calcSize(source_len: usize) usize {
        const source_len_bits = source_len * 8;
        return source_len_bits / 5 + (if (source_len_bits % 5 > 0) @as(usize, 1) else 0);
    }

    pub fn encode(dest: []u8, source: []const u8) []const u8 {
        const out_len = calcSize(source.len);
        std.debug.assert(dest.len >= out_len);

        var e = init(source);
        for (dest) |*b| b.* = e.next() orelse unreachable;
        return dest[0..out_len];
    }

    // Calculates the amount of bits can be read from `self.buffer[self.index]`,
    // with a maximum of 5 and an offset of `self.bit_off`.
    fn frontBitsLen(self: *const Self) u3 {
        // bit_off   frontBitsLen
        // 0         5
        // 1         5
        // 2         5
        // 3         5
        // 4         4
        // 5         3
        // 6         2
        // 7         1
        return if (self.bit_off <= 3) 5 else 7 - self.bit_off + 1;
    }

    // Returns the bits of `self.buffer[self.index]`, read with an offset of `self.bit_off`,
    // aligned to the left of the 5-bit unsigned integer.
    // Returns null if `self.index` is null.
    // An illustration of its behaviour, with `self.buffer[self.index]` being 0b10010111:
    // | `self.bit_off` | `frontBits` |
    // |----------------|-------------|
    // | 0              | 0b10010     |
    // | 1              | 0b00101     |
    // | 2              | 0b01011     |
    // | 3              | 0b10111     |
    // | 4              | 0b01110     |
    // | 5              | 0b11100     |
    // | 6              | 0b11000     |
    // | 7              | 0b10000     |
    fn frontBits(self: *const Self) ?u5 {
        // bit_off   bitmask      shl   shr   frontBits
        // 0         0b11111000         3     0b11111
        // 1         0b01111100         2     0b11111
        // 2         0b00111110         1     0b11111
        // 3         0b00011111   0     0     0b11111
        // 4         0b00001111   1           0b11110
        // 5         0b00000111   2           0b11100
        // 6         0b00000011   3           0b11000
        // 7         0b00000001   4           0b10000
        const index = self.index orelse return null;
        const bitmask = @as(u8, 0b11111000) >> self.bit_off;
        const bits = self.buffer[index] & bitmask;
        if (self.bit_off >= 4) return @truncate(u5, bits << (self.bit_off - 3));
        return @truncate(u5, bits >> (3 - self.bit_off));
    }

    // Returns the `self.buffer[self.index]` with the maximum amount specified by the `bits` parameter,
    // aligned to the right of the 5-bit unsigned integer.
    // Because a 5-bit integer is returned, not more than 5 bits can be read. `bits` must not be greater than 5.
    // An illustration of its behaviour, with `self.buffer[self.index]` being 0b11101001:
    // | `bits` | `backBits` |
    // |--------|------------|
    // | 0      | 0b00000    |
    // | 1      | 0b10000    |
    // | 2      | 0b11000    |
    // | 3      | 0b11100    |
    // | 4      | 0b11100    |
    // | 5      | 0b11101    |
    fn backBits(self: *const Self, bits: u3) u5 {
        std.debug.assert(bits <= 5);
        if (bits == 0 or self.index == null) return 0;
        return @truncate(u5, self.buffer[self.index.?] >> (7 - bits + 1));
    }

    // Returns the next 5-bit integer, read from `self.buffer`.
    fn next_u5(self: *Self) ?u5 {
        // `self.buffer` is read 5 bits at a time by `next_u5`.
        // Because of the elements of `self.buffer` being 8 bits each, we need to
        // read from 2 bytes from `self.buffer` to return a whole u5.
        // `front_bits` are the bits that come first, read from `self.buffer[self.index]`.
        // `back_bits` are the bits that come last, read from `self.buffer[self.index + 1]`.
        // `back_bits` is only used when we can't read 5 bits from `self.buffer[self.index]`.

        const front_bits = self.frontBits() orelse return null;
        const n_front_bits = self.frontBitsLen();

        var back_bits: u5 = 0;
        if (self.bit_off >= 3) {
            // Next time we'll need to read from the next byte in `self.buffer`.
            // We may need to grab the back bits from that next byte for this call too (if it exist).
            self.bit_off -= 3; // same as self.bit_off + 5 - 8
            const new_index = self.index.? + 1;
            if (self.buffer.len > new_index) {
                self.index = new_index;
                back_bits = self.backBits(5 - n_front_bits);
            } else {
                self.index = null;
            }
        } else {
            // We need to read from the current byte in the next call to `next_u5` too.
            self.bit_off += 5;
        }

        return front_bits | back_bits;
    }

    // Returns the corresponding ASCII character for 5 bits of the input.
    fn char(unencoded: u5) u8 {
        return unencoded + (if (unencoded < 26) @as(u8, 'A') else '2' - 26);
    }

    // Returns the next byte of the encoded buffer.
    pub fn next(self: *Self) ?u8 {
        const unencoded = self.next_u5() orelse return null;
        return char(unencoded);
    }
};

// TODO(rutgerbrf): simplify the code of the decoder

pub const DecodeError = error{CorruptInputError};

pub const Decoder = struct {
    const Self = @This();

    out_off: u4 = 0,
    buf: u8 = 0,

    pub fn read(self: *Self, c: u8) DecodeError!?u8 {
        var ret: ?u8 = null;
        var decoded_c = try decodeChar(c);
        var bits_left: u3 = 5;
        while (bits_left > 0) {
            var space_avail: u4 = 8 - self.out_off;
            var write_bits: u3 = if (bits_left < space_avail) bits_left else @truncate(u3, space_avail);
            bits_left -= write_bits;
            var mask: u8 = (@as(u8, 0x01) << write_bits) - 1;
            var want: u8 = (decoded_c >> bits_left) & mask;
            self.buf |= want << @truncate(u3, space_avail - write_bits);
            self.out_off += write_bits;
            if (self.out_off == 8) {
                ret = self.buf;
                self.out_off = 0;
                self.buf = 0;
            }
        }
        return ret;
    }

    fn decodeChar(p: u8) DecodeError!u5 {
        var value: u5 = 0;
        if (p >= 'A' and p <= 'Z') {
            value = @truncate(u5, p - @as(u8, 'A'));
        } else if (p >= '2' and p <= '9') {
            // '2' -> 26
            value = @truncate(u5, p - @as(u8, '2') + 26);
        } else {
            return error.CorruptInputError;
        }
        return value;
    }
};

pub fn decodedLen(enc_len: usize) usize {
    const enc_len_bits = enc_len * 5;
    return enc_len_bits / 8;
}

pub fn decode(ps: []const u8, out: []u8) DecodeError!usize {
    var d = Decoder{};
    var i: usize = 0;
    for (ps) |p| {
        if (i >= out.len) break;
        if (try d.read(p)) |b| {
            out[i] = b;
            i += 1;
        }
    }
    if (d.out_off != 0 and i < out.len) {
        out[i] = d.buf;
        i += 1;
    }
    return i; // amount of bytes processed
}
