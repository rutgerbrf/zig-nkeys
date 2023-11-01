const std = @import("std");
const Allocator = mem.Allocator;
const ascii = std.ascii;
const build_options = @import("build_options");
const builtin = @import("builtin");
const fs = std.fs;
const io = std.io;
const mem = std.mem;
const nkeys = @import("nkeys");
const process = std.process;
const testing = std.testing;

pub fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ format ++ "\n", args);
    process.exit(1);
}

pub fn info(comptime format: []const u8, args: anytype) void {
    std.debug.print(format ++ "\n", args);
}

const usage =
    \\Usage: znk [command] [options]
    \\
    \\Commands:
    \\
    \\  gen            Generate a new key pair
    \\  help           Print this help and exit
    \\  sign           Sign a file
    \\  verify         Verify a file with a signature
    \\  version        Print version number and exit
    \\
    \\General Options:
    \\
    \\  -h, --help     Print this help and exit
    \\
;

pub fn main() anyerror!void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(general_purpose_allocator.deinit() == .ok);
    const gpa = general_purpose_allocator.allocator();

    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    const args = try process.argsAlloc(arena);
    return mainArgs(arena, args);
}

pub fn mainArgs(arena: Allocator, args: []const []const u8) !void {
    if (args.len <= 1) {
        info("{s}", .{usage});
        fatal("expected command argument", .{});
    }

    const cmd = args[1];
    const cmd_args = args[2..];
    if (mem.eql(u8, cmd, "gen")) {
        return cmdGen(arena, cmd_args);
    } else if (mem.eql(u8, cmd, "sign")) {
        return cmdSign(arena, cmd_args);
    } else if (mem.eql(u8, cmd, "verify")) {
        return cmdVerify(arena, cmd_args);
    } else if (mem.eql(u8, cmd, "version")) {
        return io.getStdOut().writeAll(build_options.version ++ "\n");
    } else if (mem.eql(u8, cmd, "help") or mem.eql(u8, cmd, "-h") or mem.eql(u8, cmd, "--help")) {
        return io.getStdOut().writeAll(usage);
    } else {
        info("{s}", .{usage});
        fatal("unknown command: {s}", .{cmd});
    }
}

const usage_gen =
    \\Usage: znk gen [options] <role>
    \\
    \\Supported Roles:
    \\
    \\  account
    \\  cluster
    \\  operator
    \\  server
    \\  user
    \\
    \\General Options:
    \\
    \\  -h, --help     Print this help and exit
    \\
    \\Generate Options:
    \\
    \\  -e, --entropy  Path of file to get entropy from
    \\  -o, --pub-out  Print the public key to stdout
    \\  -p, --prefix   Vanity public key prefix, turns -o on
    \\
;

pub fn cmdGen(arena: Allocator, args: []const []const u8) !void {
    const stdin = io.getStdIn();
    const stdout = io.getStdOut();

    var role: ?nkeys.Role = null;
    var pub_out: bool = false;
    var prefix: ?[]const u8 = null;
    var entropy: ?fs.File = null;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.startsWith(u8, arg, "-")) {
            if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                return stdout.writeAll(usage_gen);
            } else if (mem.eql(u8, arg, "-o") or mem.eql(u8, arg, "--pub-out")) {
                pub_out = true;
            } else if (mem.eql(u8, arg, "-p") or mem.eql(u8, arg, "--prefix")) {
                if (i + 1 >= args.len)
                    fatal("expected argument after '{s}'", .{arg});
                i += 1;
                if (args[i].len > nkeys.text_public_len - 1)
                    fatal("public key prefix '{s}' is too long", .{arg});
                prefix = args[i];
            } else if (mem.eql(u8, arg, "-e") or mem.eql(u8, arg, "--entropy")) {
                if (i + 1 >= args.len) fatal("expected argument after '{s}'", .{arg});
                i += 1;
                if (entropy != null) fatal("parameter '{s}' provided more than once", .{arg});
                if (std.mem.eql(u8, args[i], "-")) {
                    entropy = stdin;
                } else {
                    entropy = fs.cwd().openFile(args[i], .{}) catch {
                        fatal("could not open entropy file at {s}", .{args[i]});
                    };
                }
            } else {
                fatal("unrecognized parameter: '{s}'", .{arg});
            }
        } else if (role != null) {
            fatal("more than one role to generate for provided", .{});
        } else if (mem.eql(u8, arg, "account")) {
            role = .account;
        } else if (mem.eql(u8, arg, "cluster")) {
            role = .cluster;
        } else if (mem.eql(u8, arg, "operator")) {
            role = .operator;
        } else if (mem.eql(u8, arg, "server")) {
            role = .server;
        } else if (mem.eql(u8, arg, "user")) {
            role = .user;
        } else {
            fatal("unrecognized extra parameter: '{s}'", .{arg});
        }
    }

    if (role == null) {
        info("{s}", .{usage_gen});
        fatal("no role to generate seed for provided", .{});
    }

    if (prefix != null) {
        const capitalized_prefix = try toUpper(arena, prefix.?);

        const entropy_reader = if (entropy) |e| e.reader() else null;
        const Generator = PrefixKeyGenerator(@TypeOf(entropy_reader.?));
        var generator = Generator.init(arena, role.?, capitalized_prefix, entropy_reader);
        generator.generate() catch {
            fatal("failed to generate key", .{});
        };
    } else {
        var gen_result = res: {
            if (entropy) |e| {
                break :res nkeys.SeedKeyPair.generateWithCustomEntropy(role.?, e.reader());
            } else {
                break :res nkeys.SeedKeyPair.generate(role.?);
            }
        };
        var kp = gen_result catch fatal("could not generate seed", .{});

        defer kp.wipe();
        try stdout.writeAll(&kp.seedText());
        try stdout.writeAll("\n");

        var public_key = kp.publicKeyText();
        if (pub_out) {
            try stdout.writeAll(&public_key);
            try stdout.writeAll("\n");
        }
    }
}

const usage_sign =
    \\Usage: znk sign -k <file> [options] <file>
    \\
    \\General Options:
    \\
    \\  -h, --help     Print this help and exit
    \\
    \\Sign Options:
    \\
    \\  -k, --key      Path of private key/seed to sign with
    \\
;

pub fn cmdSign(arena: Allocator, args: []const []const u8) !void {
    const stdin = io.getStdIn();
    const stdout = io.getStdOut();

    var file_stdin = false;
    var key_stdin = false;
    var file: ?fs.File = null;
    var key: ?fs.File = null;
    defer if (!key_stdin) if (file) |f| f.close();
    defer if (!file_stdin) if (key) |f| f.close();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.startsWith(u8, arg, "-") and arg.len > 1) {
            if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                return stdout.writeAll(usage_sign);
            } else if (mem.eql(u8, arg, "-k") or mem.eql(u8, arg, "--key")) {
                if (i + 1 >= args.len) fatal("expected argument after '{s}'", .{arg});
                i += 1;
                if (key != null) fatal("parameter '{s}' provided more than once", .{arg});
                if (std.mem.eql(u8, args[i], "-")) {
                    key = stdin;
                    key_stdin = true;
                } else {
                    key = fs.cwd().openFile(args[i], .{}) catch {
                        fatal("could not open key file at {s}", .{args[i]});
                    };
                }
            } else {
                fatal("unrecognized parameter: '{s}'", .{arg});
            }
        } else if (file != null) {
            fatal("more than one file to generate a signature for provided", .{});
        } else if (mem.eql(u8, args[i], "-")) {
            file = stdin;
            file_stdin = true;
        } else {
            file = fs.cwd().openFile(args[i], .{}) catch {
                fatal("could not open file to generate signature for (at {s})", .{args[i]});
            };
        }
    }

    if (file == null) {
        info("{s}", .{usage_sign});
        fatal("no file to generate a signature for provided", .{});
    }

    if (key == null) {
        info("{s}", .{usage_sign});
        fatal("no key to sign with provided", .{});
    }

    if (file_stdin and key_stdin) {
        fatal("can't use stdin for reading multiple files", .{});
    }

    const content = file.?.readToEndAlloc(arena, std.math.maxInt(usize)) catch {
        fatal("could not read file to generate signature for", .{});
    };
    var nkey = readKeyFile(arena, key.?) orelse fatal("could not find a valid key", .{});
    if (nkey == .public_key) fatal("key was provided but is not a seed or private key", .{});
    defer nkey.wipe();

    const sig = nkey.sign(content) catch fatal("could not generate signature", .{});
    var encoded_sig = try arena.alloc(u8, std.base64.standard.Encoder.calcSize(std.crypto.sign.Ed25519.Signature.encoded_length));
    _ = std.base64.standard.Encoder.encode(encoded_sig, &sig.toBytes());
    try stdout.writeAll(encoded_sig);
    try stdout.writeAll("\n");
}

const usage_verify =
    \\Usage: znk verify [options] <file>
    \\
    \\General Options:
    \\
    \\  -h, --help     Print this help and exit
    \\
    \\Verify Options:
    \\
    \\  -k, --key      Path of key to verify with
    \\  -s, --sig      Path of signature to verify
    \\
;

pub fn cmdVerify(arena: Allocator, args: []const []const u8) !void {
    const stdin = io.getStdIn();
    const stdout = io.getStdOut();

    var file_stdin = false;
    var key_stdin = false;
    var sig_stdin = false;
    var key: ?fs.File = null;
    var file: ?fs.File = null;
    var sig: ?fs.File = null;
    defer if (!file_stdin) if (file) |f| f.close();
    defer if (!key_stdin) if (key) |f| f.close();
    defer if (!sig_stdin) if (sig) |f| f.close();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (mem.startsWith(u8, arg, "-") and arg.len > 1) {
            if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
                return stdout.writeAll(usage_verify);
            } else if (mem.eql(u8, arg, "-k") or mem.eql(u8, arg, "--key")) {
                if (i + 1 >= args.len) fatal("expected argument after '{s}'", .{arg});
                i += 1;
                if (key != null) fatal("parameter '{s}' provided more than once", .{arg});
                if (std.mem.eql(u8, args[i], "-")) {
                    key = stdin;
                    key_stdin = true;
                } else {
                    key = fs.cwd().openFile(args[i], .{}) catch {
                        fatal("could not open file of key to verify with (at {s})", .{args[i]});
                    };
                }
            } else if (mem.eql(u8, arg, "-s") or mem.eql(u8, arg, "--sig")) {
                if (i + 1 >= args.len) fatal("expected argument after '{s}'", .{arg});
                i += 1;
                if (sig != null) fatal("parameter '{s}' provided more than once", .{arg});
                if (std.mem.eql(u8, args[i], "-")) {
                    sig = stdin;
                    sig_stdin = true;
                } else {
                    sig = fs.cwd().openFile(args[i], .{}) catch {
                        fatal("could not open signature file at {s}", .{args[i]});
                    };
                }
            } else {
                fatal("unrecognized parameter: '{s}'", .{arg});
            }
        } else if (file != null) {
            fatal("more than one file to verify signature of provided", .{});
        } else if (mem.eql(u8, args[i], "-")) {
            file = stdin;
            file_stdin = true;
        } else {
            file = fs.cwd().openFile(args[i], .{}) catch {
                fatal("could not open file to verify signature of (at {s})", .{args[i]});
            };
        }
    }

    if (file == null) {
        info("{s}", .{usage_verify});
        fatal("no file to verify signature of provided", .{});
    }

    if (key == null) {
        info("{s}", .{usage_verify});
        fatal("no key to verify signature with provided", .{});
    }

    if (sig == null) {
        info("{s}", .{usage_verify});
        fatal("no file to generate a signature for provided", .{});
    }

    if ((file_stdin and key_stdin) or (file_stdin and sig_stdin) or (key_stdin and sig_stdin)) {
        fatal("can't use stdin for reading multiple files", .{});
    }

    const content = file.?.readToEndAlloc(arena, std.math.maxInt(usize)) catch {
        fatal("could not read file to generate signature for", .{});
    };
    const signature_b64 = sig.?.readToEndAlloc(arena, std.math.maxInt(usize)) catch {
        fatal("could not read signature", .{});
    };
    var k = readKeyFile(arena, key.?) orelse fatal("could not find a valid key", .{});
    defer k.wipe();

    const trimmed_signature_b64 = mem.trim(u8, signature_b64, " \n\t\r");
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(trimmed_signature_b64) catch {
        fatal("invalid signature encoding", .{});
    };
    if (decoded_len != std.crypto.sign.Ed25519.Signature.encoded_length)
        fatal("invalid signature length", .{});

    var signature_bytes: [std.crypto.sign.Ed25519.Signature.encoded_length]u8 = undefined;
    _ = std.base64.standard.Decoder.decode(&signature_bytes, trimmed_signature_b64) catch {
        fatal("invalid signature encoding", .{});
    };

    const signature = std.crypto.sign.Ed25519.Signature.fromBytes(signature_bytes);
    k.verify(content, signature) catch {
        fatal("bad signature", .{});
    };

    try stdout.writeAll("good signature\n");
}

const RandomReader = struct {
    rand: *const std.rand.Random,

    pub const Error = error{};
    pub const Reader = io.Reader(*Self, Error, read);

    const Self = @This();

    pub fn init(rand: *const std.rand.Random) Self {
        return .{ .rand = rand };
    }

    pub fn read(self: *Self, dest: []u8) Error!usize {
        self.rand.bytes(dest);
        return dest.len;
    }

    pub fn reader(self: *Self) Reader {
        return .{ .context = self };
    }
};

fn PrefixKeyGenerator(comptime EntropyReaderType: type) type {
    return struct {
        role: nkeys.Role,
        prefix: []const u8,
        allocator: Allocator,
        done: std.atomic.Atomic(bool),
        entropy: ?EntropyReaderType,

        const Self = @This();

        pub fn init(allocator: Allocator, role: nkeys.Role, prefix: []const u8, entropy: ?EntropyReaderType) Self {
            return .{
                .role = role,
                .prefix = prefix,
                .allocator = allocator,
                .done = std.atomic.Atomic(bool).init(false),
                .entropy = entropy,
            };
        }

        fn generatePrivate(self: *Self) !void {
            var rr = RandomReader.init(&std.crypto.random);
            var brr = io.BufferedReader(1024 * 4096, @TypeOf(rr.reader())){ .unbuffered_reader = rr.reader() };
            while (!self.done.load(.SeqCst)) {
                var gen_result = if (self.entropy) |entropy|
                    nkeys.SeedKeyPair.generateWithCustomEntropy(self.role, entropy)
                else
                    nkeys.SeedKeyPair.generateWithCustomEntropy(self.role, brr.reader());
                var kp = gen_result catch fatal("could not generate seed", .{});

                var public_key = kp.publicKeyText();
                if (mem.startsWith(u8, public_key[1..], self.prefix)) {
                    if (self.done.swap(true, .SeqCst)) return; // another thread is already done

                    info("{s}", .{kp.seedText()});
                    info("{s}", .{public_key});

                    return;
                }
            }
        }

        pub usingnamespace if (builtin.single_threaded) struct {
            pub fn generate(self: *Self) !void {
                return self.generatePrivate();
            }
        } else struct {
            pub fn generate(self: *Self) !void {
                var cpu_count = try std.Thread.getCpuCount();
                var threads = try self.allocator.alloc(std.Thread, cpu_count * 4);
                defer self.allocator.free(threads);
                for (threads) |*thread| thread.* = try std.Thread.spawn(.{}, Self.generatePrivate, .{self});
                for (threads) |thread| thread.join();
            }
        };
    };
}

fn toUpper(allocator: Allocator, slice: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, slice.len);
    for (slice, 0..) |c, i| result[i] = ascii.toUpper(c);
    return result;
}

pub const Nkey = union(enum) {
    const Self = @This();

    seed_key_pair: nkeys.SeedKeyPair,
    public_key: nkeys.PublicKey,
    private_key: nkeys.PrivateKey,

    pub fn wipe(self: *Self) void {
        switch (self.*) {
            .seed_key_pair => |*kp| kp.wipe(),
            .public_key => |*pk| pk.wipe(),
            .private_key => |*pk| pk.wipe(),
        }
    }

    pub fn verify(
        self: *const Self,
        msg: []const u8,
        sig: std.crypto.sign.Ed25519.Signature,
    ) !void {
        return switch (self.*) {
            .seed_key_pair => |*kp| try kp.verify(msg, sig),
            .public_key => |*pk| try pk.verify(msg, sig),
            .private_key => |*pk| try pk.verify(msg, sig),
        };
    }

    pub fn sign(
        self: *const Self,
        msg: []const u8,
    ) !std.crypto.sign.Ed25519.Signature {
        return switch (self.*) {
            .seed_key_pair => |*kp| try kp.sign(msg),
            .private_key => |*pk| try pk.sign(msg),
            .public_key => return error.CantSign,
        };
    }

    pub fn fromText(text: []const u8) !Self {
        if (!nkeys.isValidEncoding(text)) return error.InvalidEncoding;
        switch (text[0]) {
            'S' => {
                // It's a seed.
                if (text.len != nkeys.text_seed_len) return error.InvalidSeed;
                return Self{ .seed_key_pair = try nkeys.SeedKeyPair.fromTextSeed(text[0..nkeys.text_seed_len]) };
            },
            'P' => {
                // It's a private key.
                if (text.len != nkeys.text_private_len) return error.InvalidPrivateKey;
                return Self{ .private_key = try nkeys.PrivateKey.fromTextPrivateKey(text[0..nkeys.text_private_len]) };
            },
            else => {
                // It should be a public key.
                if (text.len != nkeys.text_public_len) return error.InvalidEncoding;
                return Self{ .public_key = try nkeys.PublicKey.fromTextPublicKey(text[0..nkeys.text_public_len]) };
            },
        }
    }
};

pub fn readKeyFile(allocator: Allocator, file: fs.File) ?Nkey {
    var bytes = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch fatal("could not read key file", .{});
    defer {
        for (bytes) |*b| b.* = 0;
        allocator.free(bytes);
    }

    var iterator = mem.split(u8, bytes, "\n");
    while (iterator.next()) |line| {
        if (nkeys.isValidEncoding(line) and line.len == nkeys.text_seed_len) {
            var k = Nkey.fromText(line) catch continue;
            defer k.wipe();
            return k;
        }
    }

    return null;
}

test "reference all declarations" {
    testing.refAllDecls(@This());
    testing.refAllDecls(Nkey);
    testing.refAllDecls(PrefixKeyGenerator(std.fs.File.Reader));
}
