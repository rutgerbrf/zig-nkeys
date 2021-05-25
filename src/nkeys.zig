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
pub const InvalidPrivateKeyError = error{InvalidPrivateKey};
pub const InvalidSeedError = error{InvalidSeed};
pub const InvalidSignatureError = error{InvalidSignature};
pub const NoNkeySeedFoundError = error{NoNkeySeedFound};
pub const NoNkeyUserSeedFoundError = error{NoNkeyUserSeedFound};
pub const DecodeError = InvalidPrefixByteError || base32.DecodeError || crc16.InvalidChecksumError;
pub const SeedDecodeError = DecodeError || InvalidSeedError || crypto.errors.IdentityElementError;
pub const PrivateKeyDecodeError = DecodeError || InvalidPrivateKeyError || crypto.errors.IdentityElementError;
pub const SignError = crypto.errors.IdentityElementError || crypto.errors.WeakPublicKeyError || crypto.errors.KeyMismatchError;

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

    prefix: PublicPrefixByte,
    kp: Ed25519.KeyPair,

    pub fn generate(prefix: PublicPrefixByte) crypto.errors.IdentityElementError!Self {
        var raw_seed: [Ed25519.seed_length]u8 = undefined;
        crypto.random.bytes(&raw_seed);
        defer wipeBytes(&raw_seed);
        return Self{ .prefix = prefix, .kp = try Ed25519.KeyPair.create(raw_seed) };
    }

    pub fn fromTextSeed(text: *const text_seed) SeedDecodeError!Self {
        var decoded = try decode(2, Ed25519.seed_length, text);
        defer decoded.wipe(); // gets copied

        var key_ty_prefix = decoded.prefix[0] & 0b11111000;
        var entity_ty_prefix = (decoded.prefix[0] << 5) | (decoded.prefix[1] >> 3);

        if (key_ty_prefix != @enumToInt(KeyTypePrefixByte.seed))
            return error.InvalidSeed;

        return Self{
            .prefix = try PublicPrefixByte.fromU8(entity_ty_prefix),
            .kp = try Ed25519.KeyPair.create(decoded.data),
        };
    }

    pub fn fromRawSeed(
        prefix: PublicPrefixByte,
        raw_seed: *const [Ed25519.seed_length]u8,
    ) crypto.errors.IdentityElementError!Self {
        return Self{ .prefix = prefix, .kp = try Ed25519.KeyPair.create(raw_seed.*) };
    }

    pub fn sign(
        self: *const Self,
        msg: []const u8,
    ) SignError![Ed25519.signature_length]u8 {
        return Ed25519.sign(msg, self.kp, null);
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) InvalidSignatureError!void {
        Ed25519.verify(sig, msg, self.kp.public_key) catch return error.InvalidSignature;
    }

    pub fn seedText(self: *const Self) text_seed {
        const full_prefix = &[_]u8{
            @enumToInt(KeyTypePrefixByte.seed) | (@enumToInt(self.prefix) >> 5),
            (@enumToInt(self.prefix) & 0b00011111) << 3,
        };
        const seed = self.kp.secret_key[0..Ed25519.seed_length];
        return encode(full_prefix.len, seed.len, full_prefix, seed);
    }

    pub fn privateKeyText(self: *const Self) text_private {
        return encode(1, self.kp.secret_key.len, &[_]u8{@enumToInt(KeyTypePrefixByte.private)}, &self.kp.secret_key);
    }

    pub fn publicKeyText(self: *const Self) text_public {
        return encode(1, self.kp.public_key.len, &[_]u8{@enumToInt(self.prefix)}, &self.kp.public_key);
    }

    pub fn intoPublicKey(self: *const Self) PublicKey {
        return PublicKey{
            .prefix = self.prefix,
            .key = self.kp.public_key,
        };
    }

    pub fn intoPrivateKey(self: *const Self) PrivateKey {
        return PrivateKey{ .kp = self.kp };
    }

    pub fn wipe(self: *Self) void {
        self.prefix = .account;
        wipeKeyPair(&self.kp);
    }
};

fn wipeKeyPair(kp: *Ed25519.KeyPair) void {
    wipeBytes(&kp.public_key);
    wipeBytes(&kp.secret_key);
}

fn wipeBytes(bs: []u8) void {
    for (bs) |*b| b.* = 0;
}

pub const PublicKey = struct {
    const Self = @This();

    prefix: PublicPrefixByte,
    key: [Ed25519.public_length]u8,

    pub fn fromTextPublicKey(text: *const text_public) DecodeError!Self {
        var decoded = try decode(1, Ed25519.public_length, text);
        defer decoded.wipe(); // gets copied
        return PublicKey{
            .prefix = try PublicPrefixByte.fromU8(decoded.prefix[0]),
            .key = decoded.data,
        };
    }

    pub fn fromRawPublicKey(
        prefix: PublicPrefixByte,
        raw_key: *const [Ed25519.public_length]u8,
    ) Self {
        return Self{ .prefix = prefix, .key = raw_key.* };
    }

    pub fn publicKeyText(self: *const Self) text_public {
        return encode(1, self.key.len, &[_]u8{@enumToInt(self.prefix)}, &self.key);
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) InvalidSignatureError!void {
        Ed25519.verify(sig, msg, self.key) catch return error.InvalidSignature;
    }

    pub fn wipe(self: *Self) void {
        self.prefix = .account;
        wipeBytes(&self.key);
    }
};

pub const PrivateKey = struct {
    const Self = @This();

    kp: Ed25519.KeyPair,

    pub fn fromTextPrivateKey(text: *const text_private) PrivateKeyDecodeError!Self {
        var decoded = try decode(1, Ed25519.secret_length, text);
        defer decoded.wipe(); // gets copied
        if (decoded.prefix[0] != @enumToInt(KeyTypePrefixByte.private))
            return error.InvalidPrivateKey;
        return PrivateKey{ .kp = Ed25519.KeyPair.fromSecretKey(decoded.data) };
    }

    pub fn fromRawPrivateKey(raw_key: *const [Ed25519.secret_length]u8) Self {
        return Self{ .kp = Ed25519.KeyPair.fromSecretKey(raw_key.*) };
    }

    pub fn intoSeedKeyPair(self: *const Self, prefix: PublicPrefixByte) SeedKeyPair {
        return SeedKeyPair{
            .prefix = prefix,
            .kp = self.kp,
        };
    }

    pub fn intoPublicKey(self: *const Self, prefix: PublicPrefixByte) PublicKey {
        return PublicKey{
            .prefix = prefix,
            .key = self.kp.public_key,
        };
    }

    pub fn privateKeyText(self: *const Self) text_private {
        return encode(1, self.kp.secret_key.len, &[_]u8{@enumToInt(KeyTypePrefixByte.private)}, &self.kp.secret_key);
    }

    pub fn sign(
        self: *const Self,
        msg: []const u8,
    ) SignError![Ed25519.signature_length]u8 {
        return Ed25519.sign(msg, self.kp, null);
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: [Ed25519.signature_length]u8,
    ) InvalidSignatureError!void {
        Ed25519.verify(sig, msg, self.kp.public_key) catch return error.InvalidSignature;
    }

    pub fn wipe(self: *Self) void {
        wipeKeyPair(&self.kp);
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

pub fn isValidSeed(text: []const u8, with_type: ?PublicPrefixByte) bool {
    if (text.len < text_seed_len) return false;
    var res = SeedKeyPair.fromTextSeed(text[0..text_seed_len]) catch return false;
    defer res.wipe();
    return if (with_type) |ty| res.prefix == ty else true;
}

pub fn isValidPublicKey(text: []const u8, with_type: ?PublicPrefixByte) bool {
    if (text.len < text_public_len) return false;
    var res = PublicKey.fromTextPublicKey(text[0..text_public_len]) catch return false;
    defer res.wipe();
    return if (with_type) |ty| res.prefix == ty else true;
}

pub fn isValidPrivateKey(text: []const u8) bool {
    if (text.len < text_private_len) return false;
    var res = PrivateKey.fromTextPrivateKey(text[0..text_private_len]) catch return false;
    res.wipe();
    return true;
}

// `line` must not contain CR or LF characters.
pub fn isKeySectionBarrier(line: []const u8) bool {
    return line.len >= 6 and mem.startsWith(u8, line, "---") and mem.endsWith(u8, line, "---");
}

const allowed_creds_section_chars_table: [256]bool = allowed: {
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
    if (!mem.startsWith(u8, &key.seedText(), "SU")) return error.NoNkeyUserSeedFound;
    defer key.wipe();
    return key;
}

test {
    testing.refAllDecls(@This());
    testing.refAllDecls(SeedKeyPair);
    testing.refAllDecls(PublicKey);
    testing.refAllDecls(PrivateKey);
}

test {
    var key_pair = try SeedKeyPair.generate(PublicPrefixByte.server);
    var decoded_seed = try SeedKeyPair.fromTextSeed(&key_pair.seedText());
    try testing.expect(isValidEncoding(&decoded_seed.seedText()));

    var pub_key_str_a = key_pair.publicKeyText();
    var priv_key_str_a = key_pair.privateKeyText();
    try testing.expect(pub_key_str_a.len != 0);
    try testing.expect(priv_key_str_a.len != 0);
    try testing.expect(isValidEncoding(&pub_key_str_a));
    try testing.expect(isValidEncoding(&priv_key_str_a));

    var pub_key = key_pair.intoPublicKey();
    var pub_key_str_b = pub_key.publicKeyText();
    try testing.expectEqualStrings(&pub_key_str_a, &pub_key_str_b);

    var priv_key = key_pair.intoPrivateKey();
    var priv_key_str_b = priv_key.privateKeyText();
    try testing.expectEqualStrings(&priv_key_str_a, &priv_key_str_b);
}

test "decode" {
    const kp = try SeedKeyPair.generate(.account);
    const seed_text = kp.seedText();
    const pub_key_text = kp.publicKeyText();
    const priv_key_text = kp.privateKeyText();

    _ = try SeedKeyPair.fromTextSeed(&seed_text);
    _ = try PublicKey.fromTextPublicKey(&pub_key_text);
    _ = try PrivateKey.fromTextPrivateKey(&priv_key_text);

    try testing.expectError(error.InvalidChecksum, PublicKey.fromTextPublicKey(seed_text[0..text_public_len]));
    try testing.expectError(error.InvalidChecksum, SeedKeyPair.fromTextSeed(priv_key_text[0..text_seed_len]));
}

test "seed" {
    inline for (@typeInfo(PublicPrefixByte).Enum.fields) |field| {
        const prefix = @field(PublicPrefixByte, field.name);
        const kp = try SeedKeyPair.generate(prefix);
        const decoded = try SeedKeyPair.fromTextSeed(&kp.seedText());
        if (decoded.prefix != prefix) {
            std.debug.print("expected prefix {}, found prefix {}\n", .{ prefix, decoded.prefix });
            return error.TestUnexpectedError;
        }
    }
}

test "public key" {
    inline for (@typeInfo(PublicPrefixByte).Enum.fields) |field| {
        const prefix = @field(PublicPrefixByte, field.name);
        const kp = try SeedKeyPair.generate(prefix);
        const decoded_pub_key = try PublicKey.fromTextPublicKey(&kp.publicKeyText());
        if (decoded_pub_key.prefix != prefix) {
            std.debug.print("expected prefix {}, found prefix {}\n", .{ prefix, decoded_pub_key.prefix });
            return error.TestUnexpectedError;
        }
    }
}

test "account" {
    const kp = try SeedKeyPair.generate(.account);
    _ = try SeedKeyPair.fromTextSeed(&kp.seedText());

    const pub_key_str = kp.publicKeyText();
    try testing.expect(pub_key_str[0] == 'A');
    try testing.expect(isValidPublicKey(&pub_key_str, .account));

    const priv_key_str = kp.privateKeyText();
    try testing.expect(priv_key_str[0] == 'P');
    try testing.expect(isValidPrivateKey(&priv_key_str));

    const data = "Hello, world!";
    const sig = try kp.sign(data);
    try testing.expect(sig.len == Ed25519.signature_length);
    try kp.verify(data, sig);
}

test "cluster" {
    const kp = try SeedKeyPair.generate(.cluster);

    const pub_key_str = kp.publicKeyText();
    try testing.expect(pub_key_str[0] == 'C');
    try testing.expect(isValidPublicKey(&pub_key_str, .cluster));
}

test "operator" {
    const kp = try SeedKeyPair.generate(.operator);

    const pub_key_str = kp.publicKeyText();
    try testing.expect(pub_key_str[0] == 'O');
    try testing.expect(isValidPublicKey(&pub_key_str, .operator));
}

test "server" {
    const kp = try SeedKeyPair.generate(.server);

    const pub_key_str = kp.publicKeyText();
    try testing.expect(pub_key_str[0] == 'N');
    try testing.expect(isValidPublicKey(&pub_key_str, .server));
}

test "user" {
    const kp = try SeedKeyPair.generate(.user);

    const pub_key_str = kp.publicKeyText();
    try testing.expect(pub_key_str[0] == 'U');
    try testing.expect(isValidPublicKey(&pub_key_str, .user));
}

test "validation" {
    const prefixes = @typeInfo(PublicPrefixByte).Enum.fields;
    inline for (prefixes) |field, i| {
        const prefix = @field(PublicPrefixByte, field.name);
        const next_prefix = next: {
            const next_field_i = if (i == prefixes.len - 1) 0 else i + 1;
            std.debug.assert(next_field_i != i);
            break :next @field(PublicPrefixByte, prefixes[next_field_i].name);
        };
        const kp = try SeedKeyPair.generate(prefix);

        const seed_str = kp.seedText();
        const pub_key_str = kp.publicKeyText();
        const priv_key_str = kp.privateKeyText();

        try testing.expect(isValidSeed(&seed_str, prefix));
        try testing.expect(isValidSeed(&seed_str, null));
        try testing.expect(isValidPublicKey(&pub_key_str, null));
        try testing.expect(isValidPublicKey(&pub_key_str, prefix));
        try testing.expect(isValidPrivateKey(&priv_key_str));

        try testing.expect(!isValidSeed(&seed_str, next_prefix));
        try testing.expect(!isValidSeed(&pub_key_str, null));
        try testing.expect(!isValidSeed(&priv_key_str, null));
        try testing.expect(!isValidPublicKey(&pub_key_str, next_prefix));
        try testing.expect(!isValidPublicKey(&seed_str, null));
        try testing.expect(!isValidPublicKey(&priv_key_str, null));
        try testing.expect(!isValidPrivateKey(&seed_str));
        try testing.expect(!isValidPrivateKey(&pub_key_str));
    }

    try testing.expect(!isValidSeed("seed", null));
    try testing.expect(!isValidPublicKey("public key", null));
    try testing.expect(!isValidPrivateKey("private key"));
}

test "from seed" {
    const kp = try SeedKeyPair.generate(.account);
    const kp_from_raw = try SeedKeyPair.fromRawSeed(kp.prefix, kp.kp.secret_key[0..Ed25519.seed_length]);
    try testing.expect(std.meta.eql(kp, kp_from_raw));

    const data = "Hello, World!";
    const sig = try kp.sign(data);

    const seed = kp.seedText();
    try testing.expect(mem.startsWith(u8, &seed, "SA"));

    const kp2 = try SeedKeyPair.fromTextSeed(&seed);
    try kp2.verify(data, sig);
}

// TODO(rutgerbrf): give test a better name
test "from public key" {
    const kp = try SeedKeyPair.generate(.user);

    const pk_text = kp.publicKeyText();
    const pk_text_clone = kp.publicKeyText();
    try testing.expectEqualStrings(&pk_text, &pk_text_clone);

    const pk = try PublicKey.fromTextPublicKey(&pk_text);
    const pk_text_clone_2 = pk.publicKeyText();
    try testing.expect(std.meta.eql(pk, kp.intoPublicKey()));
    try testing.expect(std.meta.eql(pk, PublicKey.fromRawPublicKey(kp.prefix, &kp.kp.public_key)));
    try testing.expectEqualStrings(&pk_text, &pk_text_clone_2);

    const data = "Hello, world!";

    const sig = try kp.sign(data);
    try pk.verify(data, sig);

    // Create another user to sign and make sure verification fails
    const kp2 = try SeedKeyPair.generate(.user);
    const sig2 = try kp2.sign(data);

    try testing.expectError(error.InvalidSignature, pk.verify(data, sig2));
}

test "from private key" {
    const kp = try SeedKeyPair.generate(.account);

    const pk_text = kp.privateKeyText();
    const pk_text_clone = kp.privateKeyText();
    try testing.expectEqualStrings(&pk_text, &pk_text_clone);

    const pk = try PrivateKey.fromTextPrivateKey(&pk_text);
    const pk_text_clone_2 = pk.privateKeyText();
    try testing.expect(std.meta.eql(pk, kp.intoPrivateKey()));
    try testing.expect(std.meta.eql(kp, pk.intoSeedKeyPair(.account)));
    try testing.expect(std.meta.eql(pk, PrivateKey.fromRawPrivateKey(&kp.kp.secret_key)));
    try testing.expectEqualStrings(&pk_text, &pk_text_clone_2);

    const data = "Hello, World!";

    const sig0 = try kp.sign(data);
    const sig1 = try pk.sign(data);
    try testing.expectEqualSlices(u8, &sig0, &sig1);
    try pk.verify(data, sig0);
    try kp.verify(data, sig1);

    const kp2 = try SeedKeyPair.generate(.account);
    const sig2 = try kp2.sign(data);

    try testing.expectError(error.InvalidSignature, pk.verify(data, sig2));
}

// TODO(rutgerbrf): bad decode, wipe, sign, (public/private/seed) verify

test "parse decorated JWT (bad)" {
    try testing.expectEqualStrings("foo", parseDecoratedJwt("foo"));
}

test "parse decorated seed (bad)" {
    try testing.expectError(error.NoNkeySeedFound, parseDecoratedNkey("foo"));
}

test "parse decorated seed and JWT" {
    const creds =
        \\-----BEGIN NATS USER JWT-----
        \\eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJUWEg1TUxDNTdPTUJUQURYNUJNU0RLWkhSQUtXUFM0TkdHRFFPVlJXRzUyRFdaUlFFVERBIiwiaWF0IjoxNjIxNTgyOTU1LCJpc3MiOiJBQ1ZUQVZMQlFKTklQRjdNWFZWSlpZUFhaTkdFQUZMWVpTUjJSNVRZNk9ESjNSTTRYV0FDNUVFRiIsIm5hbWUiOiJ0ZXN0Iiwic3ViIjoiVUJHSlhLRkVWUlFEM05LM0lDRVc1Q0lDSzM1NkdESVZORkhaRUU0SzdMMkRYWTdORVNQVlFVNEwiLCJuYXRzIjp7InB1YiI6e30sInN1YiI6e30sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5bG9hZCI6LTEsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.OhPLDZflyJ_keg2xBRDHZZhG5x_Qf_Yb61k9eHLs9zLRf0_ETwMd0PNZI_isuBhXYevobXHVoYA3oxvMVGlDCQ
        \\------END NATS USER JWT------
        \\
        \\************************* IMPORTANT *************************
        \\NKEY Seed printed below can be used to sign and prove identity.
        \\NKEYs are sensitive and should be treated as secrets.
        \\
        \\-----BEGIN USER NKEY SEED-----
        \\SUAGIEYODKBBTUMOB666Z5KA4FCWAZV7HWSGRHOD7MK6UM5IYLWLACH7DQ
        \\------END USER NKEY SEED------
        \\
        \\*************************************************************
    ;
    const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJUWEg1TUxDNTdPTUJUQURYNUJNU0RLWkhSQUtXUFM0TkdHRFFPVlJXRzUyRFdaUlFFVERBIiwiaWF0IjoxNjIxNTgyOTU1LCJpc3MiOiJBQ1ZUQVZMQlFKTklQRjdNWFZWSlpZUFhaTkdFQUZMWVpTUjJSNVRZNk9ESjNSTTRYV0FDNUVFRiIsIm5hbWUiOiJ0ZXN0Iiwic3ViIjoiVUJHSlhLRkVWUlFEM05LM0lDRVc1Q0lDSzM1NkdESVZORkhaRUU0SzdMMkRYWTdORVNQVlFVNEwiLCJuYXRzIjp7InB1YiI6e30sInN1YiI6e30sInN1YnMiOi0xLCJkYXRhIjotMSwicGF5bG9hZCI6LTEsInR5cGUiOiJ1c2VyIiwidmVyc2lvbiI6Mn19.OhPLDZflyJ_keg2xBRDHZZhG5x_Qf_Yb61k9eHLs9zLRf0_ETwMd0PNZI_isuBhXYevobXHVoYA3oxvMVGlDCQ";
    const seed = "SUAGIEYODKBBTUMOB666Z5KA4FCWAZV7HWSGRHOD7MK6UM5IYLWLACH7DQ";

    var got_kp = try parseDecoratedUserNkey(creds);
    try testing.expectEqualStrings(seed, &got_kp.seedText());

    got_kp = try parseDecoratedNkey(creds);
    try testing.expectEqualStrings(seed, &got_kp.seedText());

    var got_jwt = parseDecoratedJwt(creds);
    try testing.expectEqualStrings(jwt, got_jwt);
}
