const std = @import("std");

pub const Encoder = struct {
    const Self = @This();

    buffer: []const u8,
    index: ?usize,
    bit_off: u3,

    fn bitmask(self: *const Self) u8 {
        return @as(u8, 0b11111000) >> self.bit_off;
    }

    fn n_front_bits(self: *const Self) u3 {
        // bit_off   n_front_bits
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

    fn front(self: *const Self, index: usize) u5 {
        // bit_off   bits         shl   shr   front
        // 0         0b11111000         3     0b11111
        // 1         0b01111100         2     0b11111
        // 2         0b00111110         1     0b11111
        // 3         0b00011111   0     0     0b11111
        // 4         0b00001111   1           0b11110
        // 5         0b00000111   2           0b11100
        // 6         0b00000011   3           0b11000
        // 7         0b00000001   4           0b10000
        const bits = self.buffer[index] & self.bitmask();
        if (self.bit_off >= 4) return @truncate(u5, bits << (self.bit_off - 3));
        return @truncate(u5, bits >> (3 - self.bit_off));
    }

    fn back(self: *const Self, index: usize, bits: u3) u5 {
        if (bits == 0) return 0;
        return @truncate(u5, self.buffer[index] >> (7 - bits + 1));
    }

    fn next_u5(self: *Self) ?u5 {
        const front_index = self.index orelse return null;
        const num_front_bits = self.n_front_bits();
        const front_bits = self.front(front_index);

        var back_bits: u5 = 0;
        if (self.bit_off >= 3) {
            self.bit_off -= 3;
            const new_index = front_index + 1;
            if (self.buffer.len > new_index) {
                self.index = new_index;
                back_bits = self.back(new_index, 5 - num_front_bits);
            } else {
                self.index = null;
            }
        } else {
            self.bit_off += 5;
        }

        return front_bits | back_bits;
    }

    fn char(unencoded: u5) u8 {
        return unencoded + (if (unencoded < 26) @as(u8, 'A') else '2' - 26);
    }

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

pub fn encodedLen(src_len: usize) usize {
    const src_len_bits = src_len * 8;
    return src_len_bits / 5 + (if (src_len_bits % 5 > 0) @as(usize, 1) else 0);
}

pub fn decodedLen(enc_len: usize) usize {
    const enc_len_bits = enc_len * 5;
    return enc_len_bits / 8;
}

pub fn encode(bs: []const u8, out: []u8) usize {
    var e = Encoder{ .buffer = bs, .index = 0, .bit_off = 0 };
    for (out) |*b, i| {
        b.* = e.next() orelse return i;
    }
    return out.len;
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
