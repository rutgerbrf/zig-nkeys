const std = @import("std");
const ascii = std.ascii;
const base32 = @import("base32.zig");
const crc16 = @import("crc16.zig");
const crypto = std.crypto;
const Ed25519 = crypto.sign.Ed25519;
const mem = std.mem;
const testing = std.testing;

const Error = error{
    InvalidPrefixByte,
    InvalidEncoding,
    InvalidSeed,
    NoNKeySeedFound,
    NoNKeyUserSeedFound,
};

pub fn fromText(text: []const u8) !Key {
    if (!isValidEncoding(text)) return error.InvalidEncoding;
    switch (text[0]) {
        'S' => {
            // It's a seed.
            if (text.len != text_seed_len) return error.InvalidSeed;
            return Key{ .seed_key_pair = try fromSeed(text[0..text_seed_len]) };
        },
        'P' => return error.InvalidEncoding, // unsupported for now
        else => {
            if (text.len != text_public_len) return error.InvalidEncoding;
            return Key{ .public_key = try fromPublicKey(text[0..text_public_len]) };
        },
    }
}

pub const Key = union(enum) {
    seed_key_pair: SeedKeyPair,
    public_key: PublicKey,

    const Self = @This();

    pub fn publicKey(self: *const Self) !text_public {
        return switch (self.*) {
            .seed_key_pair => |*kp| try kp.publicKey(),
            .public_key => |*pk| try pk.publicKey(),
        };
    }

    pub fn intoPublicKey(self: *const Self) !PublicKey {
        return switch (self.*) {
            .seed_key_pair => |*kp| try kp.intoPublicKey(),
            .public_key => |pk| pk,
        };
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) !void {
        return switch (self.*) {
            .seed_key_pair => |*kp| try kp.verify(msg, sig),
            .public_key => |*pk| try pk.verify(msg, sig),
        };
    }

    pub fn wipe(self: *Self) void {
        return switch (self.*) {
            .seed_key_pair => |*kp| kp.wipe(),
            .public_key => |*pk| pk.wipe(),
        };
    }
};

pub const KeyTypePrefixByte = enum(u8) {
    seed = 18 << 3, // S
    private = 15 << 3, // P
    unknown = 23 << 3, // U
};

pub const PublicPrefixByte = enum(u8) {
    account = 0, // A
    cluster = 2 << 3, // C
    operator = 14 << 3, // O
    server = 13 << 3, // N
    user = 20 << 3, // U

    fn fromU8(b: u8) !PublicPrefixByte {
        return switch (b) {
            @enumToInt(PublicPrefixByte.server) => .server,
            @enumToInt(PublicPrefixByte.cluster) => .cluster,
            @enumToInt(PublicPrefixByte.operator) => .operator,
            @enumToInt(PublicPrefixByte.account) => .account,
            @enumToInt(PublicPrefixByte.user) => .user,
            else => error.InvalidPrefixByte,
        };
    }
};

pub const SeedKeyPair = struct {
    const Self = @This();

    seed: text_seed,

    pub fn init(prefix: PublicPrefixByte) !Self {
        var raw_seed: [Ed25519.seed_length]u8 = undefined;
        crypto.random.bytes(&raw_seed);
        defer wipeBytes(&raw_seed);

        var seed = try encodeSeed(prefix, &raw_seed);
        return Self{ .seed = seed };
    }

    pub fn initFromSeed(seed: *const text_seed) !Self {
        var decoded = try decodeSeed(seed);
        defer decoded.wipe();

        return Self{ .seed = seed.* };
    }

    fn rawSeed(self: *const Self) ![Ed25519.seed_length]u8 {
        return (try decodeSeed(&self.seed)).seed;
    }

    fn keys(self: *const Self) !Ed25519.KeyPair {
        return Ed25519.KeyPair.create(try rawSeed(self));
    }

    pub fn privateKey(self: *const Self) !text_private {
        var kp = try self.keys();
        defer wipeKeyPair(&kp);
        return try encodePrivate(&kp.secret_key);
    }

    pub fn publicKey(self: *const Self) !text_public {
        var decoded = try decodeSeed(&self.seed);
        defer decoded.wipe();
        var kp = try Ed25519.KeyPair.create(decoded.seed);
        defer wipeKeyPair(&kp);
        return try encodePublic(decoded.prefix, &kp.public_key);
    }

    pub fn intoPublicKey(self: *const Self) !PublicKey {
        var decoded = try decodeSeed(&self.seed);
        var kp = try Ed25519.KeyPair.create(decoded.seed);
        defer wipeKeyPair(&kp);
        return PublicKey{
            .prefix = decoded.prefix,
            .key = kp.public_key,
        };
    }

    pub fn sign(
        self: *const Self,
        msg: []const u8,
    ) ![Ed25519.signature_length]u8 {
        var kp = try self.keys();
        defer wipeKeyPair(&kp);
        return try Ed25519.sign(msg, kp, null);
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) !void {
        var kp = try self.keys();
        defer wipeKeyPair(&kp);
        try Ed25519.verify(sig, msg, kp.public_key);
    }

    pub fn wipe(self: *Self) void {
        wipeBytes(&self.seed);
    }

    fn wipeKeyPair(kp: *Ed25519.KeyPair) void {
        wipeBytes(&kp.secret_key);
    }
};

fn wipeBytes(bs: []u8) void {
    for (bs) |*b| b.* = 0;
}

pub const PublicKey = struct {
    const Self = @This();

    prefix: PublicPrefixByte,
    key: [Ed25519.public_length]u8,

    pub fn publicKey(self: *const Self) !text_public {
        return try encodePublic(self.prefix, &self.key);
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) !void {
        try Ed25519.verify(sig, msg, self.key);
    }

    pub fn wipe(self: *Self) void {
        self.prefix = .user;
        std.crypto.random.bytes(&self.key);
    }
};

// One prefix byte, two CRC bytes
const binary_private_size = 1 + Ed25519.secret_length + 2;
// One prefix byte, two CRC bytes
const binary_public_size = 1 + Ed25519.public_length + 2;
// Two prefix bytes, two CRC bytes
const binary_seed_size = 2 + Ed25519.seed_length + 2;

pub const text_private_len = base32.encodedLen(binary_private_size);
pub const text_public_len = base32.encodedLen(binary_public_size);
pub const text_seed_len = base32.encodedLen(binary_seed_size);

pub const text_private = [text_private_len]u8;
pub const text_public = [text_public_len]u8;
pub const text_seed = [text_seed_len]u8;

pub fn encodePublic(prefix: PublicPrefixByte, key: *const [Ed25519.public_length]u8) !text_public {
    return encode(1, key.len, &[_]u8{@enumToInt(prefix)}, key);
}

pub fn encodePrivate(key: *const [Ed25519.secret_length]u8) !text_private {
    return encode(1, key.len, &[_]u8{@enumToInt(KeyTypePrefixByte.private)}, key);
}

fn EncodedKey(comptime prefix_len: usize, comptime data_len: usize) type {
    return [base32.encodedLen(prefix_len + data_len + 2)]u8;
}

fn encode(
    comptime prefix_len: usize,
    comptime data_len: usize,
    prefix: *const [prefix_len]u8,
    data: *const [data_len]u8,
) !EncodedKey(prefix_len, data_len) {
    var buf: [prefix_len + data_len + 2]u8 = undefined;
    defer wipeBytes(&buf);

    mem.copy(u8, &buf, prefix[0..]);
    mem.copy(u8, buf[prefix_len..], data[0..]);
    var off = prefix_len + data_len;
    var checksum = crc16.make(buf[0..off]);
    mem.writeIntLittle(u16, buf[buf.len - 2 .. buf.len], checksum);

    var text: EncodedKey(prefix_len, data_len) = undefined;
    std.debug.assert(base32.encode(&buf, &text) == text.len);

    return text;
}

pub fn encodeSeed(prefix: PublicPrefixByte, src: *const [Ed25519.seed_length]u8) !text_seed {
    var full_prefix = [_]u8{
        @enumToInt(KeyTypePrefixByte.seed) | (@enumToInt(prefix) >> 5),
        (@enumToInt(prefix) & 0b00011111) << 3,
    };
    return encode(full_prefix.len, src.len, &full_prefix, src);
}

pub fn decodePrivate(text: *const text_private) ![Ed25519.secret_length]u8 {
    var decoded = try decode(1, Ed25519.secret_length, text);
    defer wipeBytes(&decoded.data);
    if (decoded.prefix[0] != @enumToInt(KeyTypePrefixByte.private))
        return error.InvalidPrefixByte;
    return decoded.data;
}

pub fn decodePublic(prefix: PublicPrefixByte, text: *const text_public) ![Ed25519.public_length]u8 {
    var decoded = try decode(1, Ed25519.public_length, text);
    if (decoded.data[0] != @enumToInt(prefix))
        return error.InvalidPrefixByte;
    return decoded.data;
}

fn DecodedNKey(comptime prefix_len: usize, comptime data_len: usize) type {
    return struct {
        prefix: [prefix_len]u8,
        data: [data_len]u8,
    };
}

fn decode(
    comptime prefix_len: usize,
    comptime data_len: usize,
    text: *const [base32.encodedLen(prefix_len + data_len + 2)]u8,
) !DecodedNKey(prefix_len, data_len) {
    var raw: [prefix_len + data_len + 2]u8 = undefined;
    defer wipeBytes(&raw);
    std.debug.assert((try base32.decode(text[0..], &raw)) == raw.len);

    var checksum = mem.readIntLittle(u16, raw[raw.len - 2 .. raw.len]);
    try crc16.validate(raw[0 .. raw.len - 2], checksum);

    return DecodedNKey(prefix_len, data_len){
        .prefix = raw[0..prefix_len].*,
        .data = raw[prefix_len .. raw.len - 2].*,
    };
}

pub const DecodedSeed = struct {
    const Self = @This();

    prefix: PublicPrefixByte,
    seed: [Ed25519.seed_length]u8,

    pub fn wipe(self: *Self) void {
        self.prefix = .account;
        wipeBytes(&self.seed);
    }
};

pub fn decodeSeed(text: *const text_seed) !DecodedSeed {
    var decoded = try decode(2, Ed25519.seed_length, text);
    defer wipeBytes(&decoded.data); // gets copied

    var key_ty_prefix = decoded.prefix[0] & 0b11111000;
    var entity_ty_prefix = (decoded.prefix[0] & 0b00000111) << 5 | ((decoded.prefix[1] & 0b11111000) >> 3);

    if (key_ty_prefix != @enumToInt(KeyTypePrefixByte.seed))
        return error.InvalidSeed;

    return DecodedSeed{
        .prefix = try PublicPrefixByte.fromU8(entity_ty_prefix),
        .seed = decoded.data,
    };
}

pub fn fromPublicKey(text: *const text_public) !PublicKey {
    var decoded = try decode(1, Ed25519.public_length, text);
    defer wipeBytes(&decoded.data); // gets copied

    return PublicKey{
        .prefix = try PublicPrefixByte.fromU8(decoded.prefix[0]),
        .key = decoded.data,
    };
}

pub fn fromSeed(text: *const text_seed) !SeedKeyPair {
    var res = try decodeSeed(text);
    wipeBytes(&res.seed);
    return SeedKeyPair{ .seed = text.* };
}

pub fn isValidEncoding(text: []const u8) bool {
    if (text.len < 4) return false;
    var made_crc: u16 = 0;
    var dec = base32.Decoder{};
    var crc_buf: [2]u8 = undefined;
    var crc_buf_len: u8 = 0;
    var expect_len: usize = base32.decodedLen(text.len);
    var wrote_n_total: usize = 0;
    for (text) |c, i| {
        var b = (dec.read(c) catch return false) orelse continue;
        wrote_n_total += 1;
        if (crc_buf_len == 2) made_crc = crc16.update(made_crc, &.{crc_buf[0]});
        crc_buf[0] = crc_buf[1];
        crc_buf[1] = b;
        if (crc_buf_len != 2) crc_buf_len += 1;
    }
    if (dec.out_off != 0 and wrote_n_total < expect_len) {
        if (crc_buf_len == 2) made_crc = crc16.update(made_crc, &.{crc_buf[0]});
        crc_buf[0] = crc_buf[1];
        crc_buf[1] = dec.buf;
        if (crc_buf_len != 2) crc_buf_len += 1;
    }
    if (crc_buf_len != 2) unreachable;
    var got_crc = mem.readIntLittle(u16, &crc_buf);
    return made_crc == got_crc;
}

pub fn isValidSeed(text: *const text_seed) bool {
    var res = decodeSeed(text) catch return false;
    wipeBytes(&res.seed);
    return true;
}

pub fn isValidPublicKey(text: *const text_public, with_type: ?PublicPrefixByte) bool {
    var res = decode(1, Ed25519.public_length, text) catch return false;
    var public = PublicPrefixByte.fromU8(res.data[0]) catch return false;
    return if (with_type) |ty| public == ty else true;
}

pub fn fromRawSeed(prefix: PublicPrefixByte, raw_seed: *const [Ed25519.seed_length]u8) !SeedKeyPair {
    return SeedKeyPair{ .seed = try encodeSeed(prefix, raw_seed) };
}

pub fn getNextLine(text: []const u8, off: *usize) ?[]const u8 {
    if (off.* >= text.len) return null;
    var newline_pos = mem.indexOfPos(u8, text, off.*, "\n") orelse return null;
    var start = off.*;
    var end = newline_pos;
    if (newline_pos > 0 and text[newline_pos - 1] == '\r') end -= 1;
    off.* = newline_pos + 1;
    return text[start..end];
}

// `line` must not contain CR or LF characters.
pub fn isKeySectionBarrier(line: []const u8) bool {
    return line.len >= 6 and mem.startsWith(u8, line, "---") and mem.endsWith(u8, line, "---");
}

pub fn areKeySectionContentsValid(contents: []const u8) bool {
    const allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.=";

    for (contents) |c| {
        var is_c_allowed = false;
        for (allowed_chars) |allowed_c| {
            if (c == allowed_c) {
                is_c_allowed = true;
                break;
            }
        }
        if (!is_c_allowed) return false;
    }

    return true;
}

pub fn findKeySection(text: []const u8, off: *usize) ?[]const u8 {
    // Skip all space
    // Lines end with \n, but \r\n is also fine
    // Contents of the key may consist of abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.=
    // However, if a line seems to be in the form of ---stuff---, the section is ended.
    // A newline must be present at the end of the key footer
    // See https://regex101.com/r/pEaqcJ/1 for a weird edge case in the github.com/nats-io/nkeys library
    // Another weird edge case: https://regex101.com/r/Xmqj1h/1

    // TODO(rutgerbrf): switch to std.mem.SplitIterator
    while (true) {
        var opening_line = getNextLine(text, off) orelse return null;
        if (!isKeySectionBarrier(opening_line)) continue;

        var contents_line = getNextLine(text, off) orelse return null;
        if (!areKeySectionContentsValid(contents_line)) continue;

        var closing_line = getNextLine(text, off) orelse return null;
        if (!isKeySectionBarrier(closing_line)) continue;

        return contents_line;
    }
}

pub fn parseDecoratedJwt(contents: []const u8) ![]const u8 {
    var current_off: usize = 0;
    return findKeySection(contents, &current_off) orelse return contents;
}

fn validNKey(text: []const u8) bool {
    var valid_prefix =
        mem.startsWith(u8, text, "SO") or
        mem.startsWith(u8, text, "SA") or
        mem.startsWith(u8, text, "SU");
    var valid_len = text.len >= text_seed_len;
    return valid_prefix and valid_len;
}

fn findNKey(text: []const u8) ?[]const u8 {
    var current_off: usize = 0;
    while (true) {
        var line = getNextLine(text, &current_off) orelse return null;
        for (line) |c, i| {
            if (!ascii.isSpace(c)) {
                if (validNKey(line[i..])) return line[i..];
                break;
            }
        }
    }
}

pub fn parseDecoratedNKey(contents: []const u8) !SeedKeyPair {
    var current_off: usize = 0;

    var seed: ?[]const u8 = null;
    if (findKeySection(contents, &current_off) != null)
        seed = findKeySection(contents, &current_off);
    if (seed == null)
        seed = findNKey(contents) orelse return error.NoNKeySeedFound;
    if (!validNKey(seed.?))
        return error.NoNKeySeedFound;
    return fromSeed(seed.?[0..text_seed_len]);
}

pub fn parseDecoratedUserNKey(contents: []const u8) !SeedKeyPair {
    var key = try parseDecoratedNKey(contents);
    if (!mem.startsWith(u8, &key.seed, "SU")) return error.NoNKeyUserSeedFound;
    defer key.wipe();
    return key;
}

test {
    testing.refAllDecls(@This());
    testing.refAllDecls(Key);
    testing.refAllDecls(SeedKeyPair);
    testing.refAllDecls(PublicKey);
}

test {
    var key_pair = try SeedKeyPair.init(PublicPrefixByte.server);
    defer key_pair.wipe();

    var decoded_seed = try decodeSeed(&key_pair.seed);
    var encoded_second_time = try encodeSeed(decoded_seed.prefix, &decoded_seed.seed);
    try testing.expectEqualSlices(u8, &key_pair.seed, &encoded_second_time);
    try testing.expect(isValidEncoding(&key_pair.seed));

    var pub_key_str_a = try key_pair.publicKey();
    var priv_key_str = try key_pair.privateKey();
    try testing.expect(pub_key_str_a.len != 0);
    try testing.expect(priv_key_str.len != 0);
    try testing.expect(isValidEncoding(&pub_key_str_a));
    try testing.expect(isValidEncoding(&priv_key_str));
    wipeBytes(&priv_key_str);

    var pub_key = try key_pair.intoPublicKey();
    var pub_key_str_b = try pub_key.publicKey();
    try testing.expectEqualSlices(u8, &pub_key_str_a, &pub_key_str_b);
}

test {
    var creds_bytes = try std.fs.cwd().readFileAlloc(testing.allocator, "fixtures/test.creds", std.math.maxInt(usize));
    defer testing.allocator.free(creds_bytes);

    // TODO(rutgerbrf): validate the contents of the results of these functions
    _ = try parseDecoratedUserNKey(creds_bytes);
    _ = try parseDecoratedJwt(creds_bytes);
}
