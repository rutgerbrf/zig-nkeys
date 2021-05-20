const std = @import("std");

// TODO(rutgerbrf): simplify the code of the encoder & decoder?

pub const Encoder = struct {
    const Self = @This();

    out_off: u4 = 0,
    buf: u5 = 0,

    pub fn write(self: *Self, b: u8, out: []u8) usize {
        var i: usize = 0;
        var bits_left: u4 = 8;
        while (bits_left > 0) {
            var space_avail = @truncate(u3, 5 - self.out_off);
            var write_bits: u3 = if (bits_left < space_avail) @truncate(u3, bits_left) else space_avail;
            bits_left -= write_bits;
            var mask: u8 = (@as(u8, 0x01) << write_bits) - 1;
            var want: u8 = (b >> @truncate(u3, bits_left)) & mask;
            self.buf |= @truncate(u5, want << (space_avail - write_bits));
            self.out_off += write_bits;
            if (self.out_off == 5) {
                if (i >= out.len) break;
                out[i] = self.char();
                i += 1;
                self.out_off = 0;
                self.buf = 0;
            }
        }
        return i;
    }

    fn char(self: *const Self) u8 {
        return self.buf + (if (self.buf < 26) @as(u8, 'A') else '2' - 26);
    }
};

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
    var e = Encoder{};
    var i: usize = 0;
    for (bs) |b| {
        if (i >= out.len) break;
        i += e.write(b, out[i..]);
    }
    if (e.out_off != 0 and i < out.len) {
        out[i] = e.char();
        i += 1;
    }
    return i; // amount of bytes processed
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
