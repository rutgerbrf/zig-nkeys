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
pub const DecodeError = InvalidPrefixByteError || base32.DecodeError || crc16.InvalidChecksumError || crypto.errors.NonCanonicalError;
pub const SeedDecodeError = DecodeError || InvalidSeedError || crypto.errors.IdentityElementError;
pub const PrivateKeyDecodeError = DecodeError || InvalidPrivateKeyError || crypto.errors.EncodingError || crypto.errors.NonCanonicalError || crypto.errors.IdentityElementError;
pub const SignError = crypto.errors.IdentityElementError || crypto.errors.NonCanonicalError || crypto.errors.KeyMismatchError || crypto.errors.WeakPublicKeyError;

pub const prefix_byte_account = 0; // A
pub const prefix_byte_cluster = 2 << 3; // C
pub const prefix_byte_operator = 14 << 3; // O
pub const prefix_byte_private = 15 << 3; // P
pub const prefix_byte_seed = 18 << 3; // S
pub const prefix_byte_server = 13 << 3; // N
pub const prefix_byte_user = 20 << 3; // U

pub fn prefixByteToLetter(prefix_byte: u8) ?u8 {
    return switch (prefix_byte) {
        prefix_byte_account => 'A',
        prefix_byte_cluster => 'C',
        prefix_byte_operator => 'O',
        prefix_byte_private => 'P',
        prefix_byte_seed => 'S',
        prefix_byte_server => 'N',
        prefix_byte_user => 'U',
        else => null,
    };
}

pub fn prefixByteFromLetter(letter: u8) ?u8 {
    return switch (letter) {
        'A' => prefix_byte_account,
        'C' => prefix_byte_cluster,
        'O' => prefix_byte_operator,
        'P' => prefix_byte_private,
        'S' => prefix_byte_seed,
        'N' => prefix_byte_server,
        'U' => prefix_byte_user,
        else => null,
    };
}

pub const Role = enum(u8) {
    const Self = @This();

    account,
    cluster,
    operator,
    server,
    user,

    pub fn fromPublicPrefixByte(b: u8) ?Self {
        return switch (b) {
            prefix_byte_account => .account,
            prefix_byte_cluster => .cluster,
            prefix_byte_operator => .operator,
            prefix_byte_server => .server,
            prefix_byte_user => .user,
            else => null,
        };
    }

    pub fn publicPrefixByte(self: Self) u8 {
        return switch (self) {
            .account => prefix_byte_account,
            .cluster => prefix_byte_cluster,
            .operator => prefix_byte_operator,
            .server => prefix_byte_server,
            .user => prefix_byte_user,
        };
    }

    pub fn letter(self: Self) u8 {
        return prefixByteToLetter(self.publicPrefixByte()) orelse unreachable;
    }
};

// One prefix byte, two CRC bytes
const binary_private_size = 1 + Ed25519.SecretKey.encoded_length + 2;
// One prefix byte, two CRC bytes
const binary_public_size = 1 + Ed25519.PublicKey.encoded_length + 2;
// Two prefix bytes, two CRC bytes
const binary_seed_size = 2 + Ed25519.KeyPair.seed_length + 2;

pub const text_private_len = base32.Encoder.calcSize(binary_private_size);
pub const text_public_len = base32.Encoder.calcSize(binary_public_size);
pub const text_seed_len = base32.Encoder.calcSize(binary_seed_size);

pub const text_private = [text_private_len]u8;
pub const text_public = [text_public_len]u8;
pub const text_seed = [text_seed_len]u8;

pub const SeedKeyPair = struct {
    const Self = @This();

    role: Role,
    kp: Ed25519.KeyPair,

    pub fn generate(role: Role) crypto.errors.IdentityElementError!Self {
        var raw_seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
        crypto.random.bytes(&raw_seed);
        defer wipeBytes(&raw_seed);
        return Self{ .role = role, .kp = try Ed25519.KeyPair.create(raw_seed) };
    }

    pub fn generateWithCustomEntropy(role: Role, reader: anytype) !Self {
        var raw_seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
        try reader.readNoEof(&raw_seed);
        defer wipeBytes(&raw_seed);
        return Self{ .role = role, .kp = try Ed25519.KeyPair.create(raw_seed) };
    }

    pub fn fromTextSeed(text: *const text_seed) SeedDecodeError!Self {
        var decoded = try decode(2, Ed25519.KeyPair.seed_length, text);
        defer decoded.wipe(); // gets copied

        const key_ty_prefix = decoded.prefix[0] & 0b11111000;
        const role_prefix = (decoded.prefix[0] << 5) | (decoded.prefix[1] >> 3);

        if (key_ty_prefix != prefix_byte_seed)
            return error.InvalidSeed;

        const role = Role.fromPublicPrefixByte(role_prefix) orelse return error.InvalidPrefixByte;
        return fromRawSeed(role, &decoded.data);
    }

    pub fn fromRawSeed(
        role: Role,
        raw_seed: *const [Ed25519.KeyPair.seed_length]u8,
    ) crypto.errors.IdentityElementError!Self {
        return Self{ .role = role, .kp = try Ed25519.KeyPair.create(raw_seed.*) };
    }

    pub fn sign(self: *const Self, msg: []const u8) SignError!Ed25519.Signature {
        return self.kp.sign(msg, null);
    }

    pub fn verify(self: *const Self, msg: []const u8, sig: Ed25519.Signature) InvalidSignatureError!void {
        sig.verify(msg, self.kp.public_key) catch return error.InvalidSignature;
    }

    pub fn seedText(self: *const Self) text_seed {
        const public_prefix = self.role.publicPrefixByte();
        const full_prefix = &[_]u8{
            prefix_byte_seed | (public_prefix >> 5),
            (public_prefix & 0b00011111) << 3,
        };
        const seed = self.kp.secret_key.seed();
        return encode(full_prefix.len, seed.len, full_prefix, &seed);
    }

    pub fn privateKeyText(self: *const Self) text_private {
        return encode(1, Ed25519.SecretKey.encoded_length, &.{prefix_byte_private}, &self.kp.secret_key.toBytes());
    }

    pub fn publicKeyText(self: *const Self) text_public {
        return encode(1, Ed25519.PublicKey.encoded_length, &.{self.role.publicPrefixByte()}, &self.kp.public_key.toBytes());
    }

    pub fn intoPublicKey(self: *const Self) PublicKey {
        return .{
            .role = self.role,
            .key = self.kp.public_key,
        };
    }

    pub fn intoPrivateKey(self: *const Self) PrivateKey {
        return .{ .kp = self.kp };
    }

    pub fn wipe(self: *Self) void {
        self.role = .account;
        wipeKeyPair(&self.kp);
    }
};

pub const PublicKey = struct {
    const Self = @This();

    role: Role,
    key: Ed25519.PublicKey,

    pub fn fromTextPublicKey(text: *const text_public) DecodeError!Self {
        var decoded = try decode(1, Ed25519.PublicKey.encoded_length, text);
        defer decoded.wipe(); // gets copied
        return PublicKey{
            .role = Role.fromPublicPrefixByte(decoded.prefix[0]) orelse return error.InvalidPrefixByte,
            .key = try Ed25519.PublicKey.fromBytes(decoded.data),
        };
    }

    pub fn fromRawPublicKey(role: Role, raw_key: *const Ed25519.PublicKey) Self {
        return .{ .role = role, .key = raw_key.* };
    }

    pub fn publicKeyText(self: *const Self) text_public {
        return encode(1, Ed25519.PublicKey.encoded_length, &.{self.role.publicPrefixByte()}, &self.key.toBytes());
    }

    pub fn verify(self: *const Self, msg: []const u8, sig: Ed25519.Signature) InvalidSignatureError!void {
        // TODO: maybe propagate errors better herer
        sig.verify(msg, self.key) catch return error.InvalidSignature;
    }

    pub fn wipe(self: *Self) void {
        self.role = .account;
        wipeBytes(&self.key.bytes);
    }
};

pub const PrivateKey = struct {
    const Self = @This();

    kp: Ed25519.KeyPair,

    pub fn fromTextPrivateKey(text: *const text_private) PrivateKeyDecodeError!Self {
        var decoded = try decode(1, Ed25519.SecretKey.encoded_length, text);
        defer decoded.wipe(); // gets copied
        if (decoded.prefix[0] != prefix_byte_private)
            return error.InvalidPrivateKey;

        var secret_key = Ed25519.SecretKey.fromBytes(decoded.data) catch unreachable;
        return fromRawPrivateKey(&secret_key);
    }

    pub fn fromRawPrivateKey(
        raw_key: *const Ed25519.SecretKey,
    ) (crypto.errors.NonCanonicalError || crypto.errors.EncodingError || crypto.errors.IdentityElementError)!Self {
        return .{ .kp = try Ed25519.KeyPair.fromSecretKey(raw_key.*) };
    }

    pub fn intoSeedKeyPair(self: *const Self, role: Role) SeedKeyPair {
        return .{
            .role = role,
            .kp = self.kp,
        };
    }

    pub fn intoPublicKey(self: *const Self, role: Role) PublicKey {
        return .{
            .role = role,
            .key = self.kp.public_key,
        };
    }

    pub fn privateKeyText(self: *const Self) text_private {
        return encode(1, Ed25519.SecretKey.encoded_length, &.{prefix_byte_private}, &self.kp.secret_key.toBytes());
    }

    pub fn sign(self: *const Self, msg: []const u8) SignError!Ed25519.Signature {
        return self.kp.sign(msg, null);
    }

    pub fn verify(self: *const Self, msg: []const u8, sig: Ed25519.Signature) InvalidSignatureError!void {
        sig.verify(msg, self.kp.public_key) catch return error.InvalidSignature;
    }

    pub fn wipe(self: *Self) void {
        wipeKeyPair(&self.kp);
    }
};

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

    mem.copyForwards(u8, &buf, prefix[0..]);
    mem.copyForwards(u8, buf[prefix_len..], data[0..]);
    const off = prefix_len + data_len;
    const checksum = crc16.make(buf[0..off]);
    mem.writeInt(u16, buf[buf.len - 2 .. buf.len], checksum, .little);

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
            self.prefix[0] = Role.account.publicPrefixByte();
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

    const checksum = mem.readInt(u16, raw[raw.len - 2 .. raw.len], .little);
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
    const expect_len: usize = base32.Decoder.calcSize(text.len);
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
    const got_crc = mem.readInt(u16, &crc_buf, .little);
    return made_crc == got_crc;
}

pub fn isValidSeed(text: []const u8, with_role: ?Role) bool {
    if (text.len < text_seed_len) return false;
    var res = SeedKeyPair.fromTextSeed(text[0..text_seed_len]) catch return false;
    defer res.wipe();
    return if (with_role) |role| res.role == role else true;
}

pub fn isValidPublicKey(text: []const u8, with_role: ?Role) bool {
    if (text.len < text_public_len) return false;
    var res = PublicKey.fromTextPublicKey(text[0..text_public_len]) catch return false;
    defer res.wipe();
    return if (with_role) |role| res.role == role else true;
}

pub fn isValidPrivateKey(text: []const u8) bool {
    if (text.len < text_private_len) return false;
    var res = PrivateKey.fromTextPrivateKey(text[0..text_private_len]) catch return false;
    res.wipe();
    return true;
}

// `line` must not contain CR or LF characters.
pub fn isKeySectionBarrier(line: []const u8, opening: bool) bool {
    if (line.len < 6) return false;
    const start = mem.indexOf(u8, line, "---") orelse return false;
    if (!opening and start != 0) return false;
    if (line.len - start < 6) return false;
    return mem.endsWith(u8, line, "---");
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

pub fn findKeySection(line_it: *std.mem.SplitIterator(u8, .scalar)) ?[]const u8 {
    while (true) {
        const opening_line = line_it.next() orelse return null;
        if (!isKeySectionBarrier(opening_line, true)) continue;

        const contents_line = line_it.next() orelse return null;
        if (!areKeySectionContentsValid(contents_line)) continue;

        const closing_line = line_it.next() orelse return null;
        if (!isKeySectionBarrier(closing_line, false)) continue;

        return contents_line;
    }
}

pub fn parseDecoratedJwt(contents: []const u8) []const u8 {
    var line_it = mem.splitScalar(u8, contents, '\n');
    return findKeySection(&line_it) orelse return contents;
}

pub fn parseDecoratedNkey(contents: []const u8) NoNkeySeedFoundError!SeedKeyPair {
    var line_it = mem.splitScalar(u8, contents, '\n');
    var seed: ?[]const u8 = null;
    if (findKeySection(&line_it) != null)
        seed = findKeySection(&line_it);
    if (seed == null)
        seed = findNkey(contents) orelse return error.NoNkeySeedFound;
    if (!isValidCredsNkey(seed.?))
        return error.NoNkeySeedFound;
    return SeedKeyPair.fromTextSeed(seed.?[0..text_seed_len]) catch return error.NoNkeySeedFound;
}

pub fn parseDecoratedUserNkey(contents: []const u8) (NoNkeySeedFoundError || NoNkeyUserSeedFoundError)!SeedKeyPair {
    var key = try parseDecoratedNkey(contents);
    if (!mem.startsWith(u8, &key.seedText(), "SU")) return error.NoNkeyUserSeedFound;
    defer key.wipe();
    return key;
}

fn isValidCredsNkey(text: []const u8) bool {
    const valid_prefix =
        mem.startsWith(u8, text, "SO") or
        mem.startsWith(u8, text, "SA") or
        mem.startsWith(u8, text, "SU");
    const valid_len = text.len >= text_seed_len;
    return valid_prefix and valid_len;
}

fn findNkey(text: []const u8) ?[]const u8 {
    var line_it = std.mem.split(u8, text, "\n");
    while (line_it.next()) |line| {
        for (line, 0..) |c, i| {
            if (!ascii.isWhitespace(c)) {
                if (isValidCredsNkey(line[i..])) return line[i..];
                break;
            }
        }
    }
    return null;
}

fn wipeKeyPair(kp: *Ed25519.KeyPair) void {
    wipeBytes(&kp.public_key.bytes);
    wipeBytes(&kp.secret_key.bytes);
}

fn wipeBytes(bs: []u8) void {
    for (bs) |*b| b.* = 0;
}

test "reference all declarations" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Role);
    testing.refAllDecls(SeedKeyPair);
    testing.refAllDecls(PublicKey);
    testing.refAllDecls(PrivateKey);
}

test "key conversions" {
    var key_pair = try SeedKeyPair.generate(.server);
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
    inline for (@typeInfo(Role).Enum.fields) |field| {
        const role = @field(Role, field.name);
        const kp = try SeedKeyPair.generate(role);
        const decoded = try SeedKeyPair.fromTextSeed(&kp.seedText());
        if (decoded.role != role) {
            std.debug.print("expected role {}, found role {}\n", .{ role, decoded.role });
            return error.TestUnexpectedError;
        }
    }
}

test "public key" {
    inline for (@typeInfo(Role).Enum.fields) |field| {
        const role = @field(Role, field.name);
        const kp = try SeedKeyPair.generate(role);
        const decoded_pub_key = try PublicKey.fromTextPublicKey(&kp.publicKeyText());
        if (decoded_pub_key.role != role) {
            std.debug.print("expected role {}, found role {}\n", .{ role, decoded_pub_key.role });
            return error.TestUnexpectedError;
        }
    }
}

test "different key types" {
    inline for (@typeInfo(Role).Enum.fields) |field| {
        const role = @field(Role, field.name);

        const kp = try SeedKeyPair.generate(role);
        _ = try SeedKeyPair.fromTextSeed(&kp.seedText());

        const pub_key_str = kp.publicKeyText();
        try testing.expect(pub_key_str[0] == role.letter());
        try testing.expect(isValidPublicKey(&pub_key_str, role));

        const priv_key_str = kp.privateKeyText();
        try testing.expect(priv_key_str[0] == 'P');
        try testing.expect(isValidPrivateKey(&priv_key_str));

        const data = "Hello, world!";
        const sig = try kp.sign(data);
        try testing.expect(sig.toBytes().len == Ed25519.Signature.encoded_length);
        try kp.verify(data, sig);
    }
}

test "validation" {
    const roles = @typeInfo(Role).Enum.fields;
    inline for (roles, 0..) |field, i| {
        const role = @field(Role, field.name);
        const next_role = next: {
            const next_field_i = if (i == roles.len - 1) 0 else i + 1;
            std.debug.assert(next_field_i != i);
            break :next @field(Role, roles[next_field_i].name);
        };
        const kp = try SeedKeyPair.generate(role);

        const seed_str = kp.seedText();
        const pub_key_str = kp.publicKeyText();
        const priv_key_str = kp.privateKeyText();

        try testing.expect(isValidSeed(&seed_str, role));
        try testing.expect(isValidSeed(&seed_str, null));
        try testing.expect(isValidPublicKey(&pub_key_str, null));
        try testing.expect(isValidPublicKey(&pub_key_str, role));
        try testing.expect(isValidPrivateKey(&priv_key_str));

        try testing.expect(!isValidSeed(&seed_str, next_role));
        try testing.expect(!isValidSeed(&pub_key_str, null));
        try testing.expect(!isValidSeed(&priv_key_str, null));
        try testing.expect(!isValidPublicKey(&pub_key_str, next_role));
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
    const kp_from_raw = try SeedKeyPair.fromRawSeed(kp.role, &kp.kp.secret_key.seed());
    try testing.expect(std.meta.eql(kp, kp_from_raw));

    const data = "Hello, World!";
    const sig = try kp.sign(data);

    const seed = kp.seedText();
    try testing.expect(mem.startsWith(u8, &seed, "SA"));

    const kp2 = try SeedKeyPair.fromTextSeed(&seed);
    try kp2.verify(data, sig);
}

test "from public key" {
    const kp = try SeedKeyPair.generate(.user);

    const pk_text = kp.publicKeyText();
    const pk_text_clone = kp.publicKeyText();
    try testing.expectEqualStrings(&pk_text, &pk_text_clone);

    const pk = try PublicKey.fromTextPublicKey(&pk_text);
    const pk_text_clone_2 = pk.publicKeyText();
    try testing.expect(std.meta.eql(pk, kp.intoPublicKey()));
    try testing.expect(std.meta.eql(pk, PublicKey.fromRawPublicKey(kp.role, &kp.kp.public_key)));
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
    try testing.expect(std.meta.eql(pk, try PrivateKey.fromRawPrivateKey(&kp.kp.secret_key)));
    try testing.expectEqualStrings(&pk_text, &pk_text_clone_2);

    const data = "Hello, World!";

    const sig0 = try kp.sign(data);
    const sig1 = try pk.sign(data);
    try testing.expectEqualSlices(u8, &sig0.toBytes(), &sig1.toBytes());
    try pk.verify(data, sig0);
    try kp.verify(data, sig1);

    const kp2 = try SeedKeyPair.generate(.account);
    const sig2 = try kp2.sign(data);

    try testing.expectError(error.InvalidSignature, pk.verify(data, sig2));
}

test "bad decode" {
    const kp = try SeedKeyPair.fromTextSeed("SAAHPQF3GOP4IP5SHKHCNBOHD5TMGSW4QQL6RTZAPEEYOQ2NRBIAKCCLQA");

    var bad_seed = kp.seedText();
    bad_seed[1] = 'S';
    try testing.expectError(error.InvalidChecksum, SeedKeyPair.fromTextSeed(&bad_seed));

    var bad_pub_key = kp.publicKeyText();
    bad_pub_key[bad_pub_key.len - 1] = 'O';
    bad_pub_key[bad_pub_key.len - 2] = 'O';
    try testing.expectError(error.InvalidChecksum, PublicKey.fromTextPublicKey(&bad_pub_key));

    var bad_priv_key = kp.privateKeyText();
    bad_priv_key[bad_priv_key.len - 1] = 'O';
    bad_priv_key[bad_priv_key.len - 2] = 'O';
    try testing.expectError(error.InvalidChecksum, PrivateKey.fromTextPrivateKey(&bad_priv_key));
}

test "wipe" {
    const kp = try SeedKeyPair.generate(.account);
    const pub_key = kp.intoPublicKey();
    const priv_key = kp.intoPrivateKey();

    var kp_clone = kp;
    kp_clone.wipe();
    try testing.expect(!std.meta.eql(kp_clone.kp, kp.kp));

    var pub_key_clone = pub_key;
    pub_key_clone.wipe();
    try testing.expect(!std.meta.eql(pub_key_clone.key, pub_key.key));

    var priv_key_clone = priv_key;
    priv_key_clone.wipe();
    try testing.expect(!std.meta.eql(priv_key_clone.kp, priv_key.kp));
}

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

    const got_jwt = parseDecoratedJwt(creds);
    try testing.expectEqualStrings(jwt, got_jwt);
}
