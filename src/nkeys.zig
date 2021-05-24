const std = @import("std");
const ascii = std.ascii;
const base32 = @import("base32.zig");
const crc16 = @import("crc16.zig");
const crypto = std.crypto;
const Ed25519 = crypto.sign.Ed25519;
const mem = std.mem;
const testing = std.testing;

pub const InvalidPrefixByteError = error{InvalidPrefixByte};
pub const InvalidEncodingError = error{InvalidEncoding};
pub const InvalidSeedError = error{InvalidSeed};
pub const NoNkeySeedFoundError = error{NoNkeySeedFound};
pub const NoNkeyUserSeedFoundError = error{NoNkeyUserSeedFound};

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

    fn fromU8(b: u8) error{InvalidPrefixByte}!PublicPrefixByte {
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

    pub fn generate(prefix: PublicPrefixByte) Self {
        var raw_seed: [Ed25519.seed_length]u8 = undefined;
        crypto.random.bytes(&raw_seed);
        defer wipeBytes(&raw_seed);

        return Self{ .seed = encodeSeed(prefix, &raw_seed) };
    }

    pub fn fromTextSeed(seed: *const text_seed) SeedDecodeError!Self {
        var decoded = try decodeSeed(seed);
        decoded.wipe();
        return Self{ .seed = seed.* };
    }

    pub fn fromRawSeed(prefix: PublicPrefixByte, raw_seed: *const [Ed25519.seed_length]u8) Self {
        return Self{ .seed = encodeSeed(prefix, raw_seed) };
    }

    fn rawSeed(self: *const Self) SeedDecodeError![Ed25519.seed_length]u8 {
        return (try decodeSeed(&self.seed)).seed;
    }

    fn keys(self: *const Self) (SeedDecodeError || crypto.errors.IdentityElementError)!Ed25519.KeyPair {
        return Ed25519.KeyPair.create(try rawSeed(self));
    }

    pub fn privateKey(self: *const Self) (SeedDecodeError || crypto.errors.IdentityElementError)!text_private {
        var kp = try self.keys();
        defer wipeKeyPair(&kp);
        return encodePrivate(&kp.secret_key);
    }

    pub fn publicKey(self: *const Self) (SeedDecodeError || crypto.errors.IdentityElementError)!text_public {
        var decoded = try decodeSeed(&self.seed);
        defer decoded.wipe();
        var kp = try Ed25519.KeyPair.create(decoded.seed);
        defer wipeKeyPair(&kp);
        return encodePublic(decoded.prefix, &kp.public_key);
    }

    pub fn intoPublicKey(self: *const Self) (SeedDecodeError || crypto.errors.IdentityElementError)!PublicKey {
        var decoded = try decodeSeed(&self.seed);
        defer decoded.wipe();
        var kp = try Ed25519.KeyPair.create(decoded.seed);
        defer wipeKeyPair(&kp);
        return PublicKey{
            .prefix = decoded.prefix,
            .key = kp.public_key,
        };
    }

    pub const SignError = SeedDecodeError || crypto.errors.IdentityElementError || crypto.errors.WeakPublicKeyError;

    pub fn sign(
        self: *const Self,
        msg: []const u8,
    ) SignError![Ed25519.signature_length]u8 {
        var kp = try self.keys();
        defer wipeKeyPair(&kp);
        return Ed25519.sign(msg, kp, null) catch |e| switch (e) {
            error.KeyMismatch => unreachable, // would mean that self.keys() has an incorrect implementation
            error.WeakPublicKey => error.WeakPublicKey,
            error.IdentityElement => error.IdentityElement,
        };
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) !void {
        var kp = try self.keys();
        defer wipeKeyPair(&kp);
        Ed25519.verify(sig, msg, kp.public_key) catch return error.InvalidSignature;
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

    pub fn fromTextPublicKey(text: *const text_public) DecodeError!PublicKey {
        var decoded = try decode(1, Ed25519.public_length, text);
        defer decoded.wipe(); // gets copied
        return PublicKey{
            .prefix = try PublicPrefixByte.fromU8(decoded.prefix[0]),
            .key = decoded.data,
        };
    }

    pub fn publicKey(self: *const Self) text_public {
        return encodePublic(self.prefix, &self.key);
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) !void {
        Ed25519.verify(sig, msg, self.key) catch return error.InvalidSignature;
    }

    pub fn wipe(self: *Self) void {
        self.prefix = .account;
        wipeBytes(&self.key);
    }
};

// One prefix byte, two CRC bytes
const binary_private_size = 1 + Ed25519.secret_length + 2;
// One prefix byte, two CRC bytes
const binary_public_size = 1 + Ed25519.public_length + 2;
// Two prefix bytes, two CRC bytes
const binary_seed_size = 2 + Ed25519.seed_length + 2;

pub const text_private_len = base32.Encoder.calcSize(binary_private_size);
pub const text_public_len = base32.Encoder.calcSize(binary_public_size);
pub const text_seed_len = base32.Encoder.calcSize(binary_seed_size);

pub const text_private = [text_private_len]u8;
pub const text_public = [text_public_len]u8;
pub const text_seed = [text_seed_len]u8;

fn encodePublic(prefix: PublicPrefixByte, key: *const [Ed25519.public_length]u8) text_public {
    return encode(1, key.len, &[_]u8{@enumToInt(prefix)}, key);
}

fn encodePrivate(key: *const [Ed25519.secret_length]u8) text_private {
    return encode(1, key.len, &[_]u8{@enumToInt(KeyTypePrefixByte.private)}, key);
}

fn encoded_key(comptime prefix_len: usize, comptime data_len: usize) type {
    return [base32.Encoder.calcSize(prefix_len + data_len + 2)]u8;
}

fn encode(
    comptime prefix_len: usize,
    comptime data_len: usize,
    prefix: *const [prefix_len]u8,
    data: *const [data_len]u8,
) encoded_key(prefix_len, data_len) {
    var buf: [prefix_len + data_len + 2]u8 = undefined;
    defer wipeBytes(&buf);

    mem.copy(u8, &buf, prefix[0..]);
    mem.copy(u8, buf[prefix_len..], data[0..]);
    var off = prefix_len + data_len;
    var checksum = crc16.make(buf[0..off]);
    mem.writeIntLittle(u16, buf[buf.len - 2 .. buf.len], checksum);

    var text: encoded_key(prefix_len, data_len) = undefined;
    std.debug.assert(base32.Encoder.encode(&text, &buf).len == text.len);

    return text;
}

pub fn encodeSeed(prefix: PublicPrefixByte, src: *const [Ed25519.seed_length]u8) text_seed {
    const full_prefix = &[_]u8{
        @enumToInt(KeyTypePrefixByte.seed) | (@enumToInt(prefix) >> 5),
        (@enumToInt(prefix) & 0b00011111) << 3,
    };
    return encode(full_prefix.len, src.len, full_prefix, src);
}

pub const DecodeError = InvalidPrefixByteError || base32.DecodeError || crc16.InvalidChecksumError;

fn DecodedNkey(comptime prefix_len: usize, comptime data_len: usize) type {
    return struct {
        const Self = @This();

        prefix: [prefix_len]u8,
        data: [data_len]u8,

        pub fn wipe(self: *Self) void {
            self.prefix[0] = @enumToInt(PublicPrefixByte.account);
            wipeBytes(&self.data);
        }
    };
}

fn decode(
    comptime prefix_len: usize,
    comptime data_len: usize,
    text: *const [base32.Encoder.calcSize(prefix_len + data_len + 2)]u8,
) (base32.DecodeError || crc16.InvalidChecksumError)!DecodedNkey(prefix_len, data_len) {
    var raw: [prefix_len + data_len + 2]u8 = undefined;
    defer wipeBytes(&raw);
    std.debug.assert((try base32.Decoder.decode(&raw, text[0..])).len == raw.len);

    var checksum = mem.readIntLittle(u16, raw[raw.len - 2 .. raw.len]);
    try crc16.validate(raw[0 .. raw.len - 2], checksum);

    return DecodedNkey(prefix_len, data_len){
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

pub const SeedDecodeError = DecodeError || InvalidSeedError;

pub fn decodeSeed(text: *const text_seed) SeedDecodeError!DecodedSeed {
    var decoded = try decode(2, Ed25519.seed_length, text);
    defer decoded.wipe(); // gets copied

    var key_ty_prefix = decoded.prefix[0] & 0b11111000;
    var entity_ty_prefix = (decoded.prefix[0] & 0b00000111) << 5 | ((decoded.prefix[1] & 0b11111000) >> 3);

    if (key_ty_prefix != @enumToInt(KeyTypePrefixByte.seed))
        return error.InvalidSeed;

    return DecodedSeed{
        .prefix = try PublicPrefixByte.fromU8(entity_ty_prefix),
        .seed = decoded.data,
    };
}

pub fn isValidEncoding(text: []const u8) bool {
    if (text.len < 4) return false;
    var made_crc: u16 = 0;
    var dec = base32.Decoder.init(text);
    var crc_buf: [2]u8 = undefined;
    var crc_buf_len: u8 = 0;
    var expect_len: usize = base32.Decoder.calcSize(text.len);
    var wrote_n_total: usize = 0;
    while (dec.next() catch return false) |b| {
        wrote_n_total += 1;
        if (crc_buf_len == 2) made_crc = crc16.update(made_crc, &.{crc_buf[0]});
        crc_buf[0] = crc_buf[1];
        crc_buf[1] = b;
        if (crc_buf_len != 2) crc_buf_len += 1;
    }
    std.debug.assert(wrote_n_total == expect_len);
    if (crc_buf_len != 2) unreachable;
    var got_crc = mem.readIntLittle(u16, &crc_buf);
    return made_crc == got_crc;
}

pub fn isValidSeed(text: *const text_seed) bool {
    var res = decodeSeed(text) catch return false;
    res.wipe();
    return true;
}

pub fn isValidPublicKey(text: *const text_public, with_type: ?PublicPrefixByte) bool {
    var res = decode(1, Ed25519.public_length, text) catch return false;
    defer res.wipe();
    const public = PublicPrefixByte.fromU8(res.data[0]) catch return false;
    return if (with_type) |ty| public == ty else true;
}

// `line` must not contain CR or LF characters.
pub fn isKeySectionBarrier(line: []const u8) bool {
    return line.len >= 6 and mem.startsWith(u8, line, "---") and mem.endsWith(u8, line, "---");
}

const allowed_creds_section_chars_table: [256]bool = allowed: {
    @setEvalBranchQuota(256);

    var table = [_]bool{false} ** 256;
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.=";
    for (chars) |char| table[char] = true;

    break :allowed table;
};

pub fn areKeySectionContentsValid(contents: []const u8) bool {
    for (contents) |c| if (!allowed_creds_section_chars_table[c]) return false;
    return true;
}

pub fn findKeySection(text: []const u8, line_it: *std.mem.SplitIterator) ?[]const u8 {
    // TODO(rutgerbrf): There is a weird edge case in the github.com/nats-io/nkeys library,
    // see https://regex101.com/r/pEaqcJ/1. It allows the opening barrier to start at an
    // arbitrary point on the line, meaning that `asdf-----BEGIN USER NKEY SEED-----`
    // is regarded as a valid opening barrier by the library.
    // Should we accept a creds file formatted in such a manner?

    while (true) {
        const opening_line = line_it.next() orelse return null;
        if (!isKeySectionBarrier(opening_line)) continue;

        const contents_line = line_it.next() orelse return null;
        if (!areKeySectionContentsValid(contents_line)) continue;

        const closing_line = line_it.next() orelse return null;
        if (!isKeySectionBarrier(closing_line)) continue;

        return contents_line;
    }
}

pub fn parseDecoratedJwt(contents: []const u8) []const u8 {
    var line_it = mem.split(contents, "\n");
    return findKeySection(contents, &line_it) orelse return contents;
}

fn validNkey(text: []const u8) bool {
    const valid_prefix =
        mem.startsWith(u8, text, "SO") or
        mem.startsWith(u8, text, "SA") or
        mem.startsWith(u8, text, "SU");
    const valid_len = text.len >= text_seed_len;
    return valid_prefix and valid_len;
}

fn findNkey(text: []const u8) ?[]const u8 {
    var line_it = std.mem.split(text, "\n");
    var current_off: usize = 0;
    while (line_it.next()) |line| {
        for (line) |c, i| {
            if (!ascii.isSpace(c)) {
                if (validNkey(line[i..])) return line[i..];
                break;
            }
        }
    }
    return null;
}

pub fn parseDecoratedNkey(contents: []const u8) NoNkeySeedFoundError!SeedKeyPair {
    var line_it = mem.split(contents, "\n");
    var current_off: usize = 0;
    var seed: ?[]const u8 = null;
    if (findKeySection(contents, &line_it) != null)
        seed = findKeySection(contents, &line_it);
    if (seed == null)
        seed = findNkey(contents) orelse return error.NoNkeySeedFound;
    if (!validNkey(seed.?))
        return error.NoNkeySeedFound;
    return SeedKeyPair.fromTextSeed(seed.?[0..text_seed_len]) catch return error.NoNkeySeedFound;
}

pub fn parseDecoratedUserNkey(contents: []const u8) (NoNkeySeedFoundError || NoNkeyUserSeedFoundError)!SeedKeyPair {
    var key = try parseDecoratedNkey(contents);
    if (!mem.startsWith(u8, &key.seed, "SU")) return error.NoNkeyUserSeedFound;
    defer key.wipe();
    return key;
}

test {
    testing.refAllDecls(@This());
    testing.refAllDecls(SeedKeyPair);
    testing.refAllDecls(PublicKey);
}

test {
    var key_pair = SeedKeyPair.generate(PublicPrefixByte.server);
    defer key_pair.wipe();

    var decoded_seed = try decodeSeed(&key_pair.seed);
    defer decoded_seed.wipe();
    var encoded_second_time = encodeSeed(decoded_seed.prefix, &decoded_seed.seed);
    defer wipeBytes(&encoded_second_time);
    try testing.expectEqualSlices(u8, &key_pair.seed, &encoded_second_time);
    try testing.expect(isValidEncoding(&key_pair.seed));

    var pub_key_str_a = try key_pair.publicKey();
    defer wipeBytes(&pub_key_str_a);
    var priv_key_str = try key_pair.privateKey();
    defer wipeBytes(&priv_key_str);
    try testing.expect(pub_key_str_a.len != 0);
    try testing.expect(priv_key_str.len != 0);
    try testing.expect(isValidEncoding(&pub_key_str_a));
    try testing.expect(isValidEncoding(&priv_key_str));

    var pub_key = try key_pair.intoPublicKey();
    defer pub_key.wipe();
    var pub_key_str_b = pub_key.publicKey();
    defer wipeBytes(&pub_key_str_b);
    try testing.expectEqualSlices(u8, &pub_key_str_a, &pub_key_str_b);
}

test {
    var creds_bytes = try std.fs.cwd().readFileAlloc(testing.allocator, "fixtures/test.creds", std.math.maxInt(usize));
    defer testing.allocator.free(creds_bytes);
    defer wipeBytes(creds_bytes);

    // TODO(rutgerbrf): validate the contents of the results of these functions
    _ = try parseDecoratedUserNkey(creds_bytes);
    _ = parseDecoratedJwt(creds_bytes);
}
