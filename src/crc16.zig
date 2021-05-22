const Error = error{InvalidChecksum};

const crc16tab: [256]u16 = tab: {
    @setEvalBranchQuota(10000);

    // CRC-16-CCITT/XMODEM
    const poly: u32 = 0x1021;
    var table: [256]u16 = undefined;

    for (table) |*crc, i| {
        crc.* = @as(u16, i) << 8;
        var j = 0;
        while (j < 8) : (j += 1) {
            if (crc.* >> 15 != 0) {
                crc.* = (crc.* << 1) ^ poly;
            } else {
                crc.* <<= 1;
            }
        }
    }

    break :tab table;
};

pub fn update(crc: u16, with_data: []const u8) u16 {
    var new_crc = crc;
    for (with_data) |b| {
        new_crc = (new_crc << 8) ^ crc16tab[@truncate(u8, new_crc >> 8) ^ b];
    }
    return new_crc;
}

// make returns the CRC16 checksum for the data provided.
pub fn make(data: []const u8) u16 {
    return update(0, data);
}

// validate will check the calculated CRC16 checksum for data against the expected.
pub fn validate(data: []const u8, expected: u16) !void {
    if (make(data) != expected) return error.InvalidChecksum;
}
