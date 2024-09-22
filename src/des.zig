// based on: DES encryption/decryption cli tool written in zig, by JungerBoyo
// https://github.com/JungerBoyo/DES/blob/main/src/main.zig

// DES is not secure, this is only for compatibility with the unencrypted VNC protocol.

const std = @import("std");

pub fn init_encrypt(key: u64, subkeys: *[16]u48) void {
    generateKeys(key, subkeys);
}

pub fn init_decrypt(key: u64, subkeys: *[16]u48) void {
    generateKeys(key, subkeys);
    std.mem.reverse(u48, subkeys[0..]);
}

pub fn process_8bytes(block: *[8]u8, subkeys: *const [16]u48) void {
    const block_as_int: u64 = std.mem.readInt(u64, block, .big);
    var out: u64 = 0;
    for (0..8) |row| {
        for (0..8) |col| {
            const IP_from_64: u6 = @intCast(IP_first_col[row] + (col * 8));  // = 63 - (IP - 1)
            out = (out << 1) | ((block_as_int >> IP_from_64) & 0x1);
        }
    }
    for (0..16) |i| out = (out << 32) | ((out >> 32) ^ applyFeistelRound(@truncate(out), subkeys[i]));
    const after_16_rounds = out;  // the final swap of left/right 32 bit is handled by the IP_1 table.
    for (0..8) |row| {
        for (0..8) |col| {
            const IP_1_from_64:u6 = @intCast(@as(u6, IP_1_first_row[col]) * 8 + row);  // = 63 - (IP_1 - 1)        
            out = (out << 1) | ((after_16_rounds >> IP_1_from_64) & 0x1); // old value will be shifted out.
        }
    }
    std.mem.writeInt(u64, block, out, .big);
}

fn generateKeys(key: u64, subkeys: *[16]u48) void {
    var stripped_key: u56 = 0;
    for (0..7) |row| {
        for (0..8) |col| {
            const PC1_from_64:u6 = @intCast(PC1_col_0and4[row][col >> 2] + ((col & 0b11) * 8));  // = 63 - (PC1 - 1)        
            stripped_key = (stripped_key << 1) | @as(u1, @intCast((key >> PC1_from_64) & 0x1));
        }
    }
    for (0..16) |i| { 
        const extra_rotation: usize = (@as(u16, 0b01111110_11111100) >> @intCast(i)) & 0x1;
        for (0..1+extra_rotation) |_| stripped_key = ((stripped_key & 0x7FFFFFF_7FFFFFF) <<  1) |
                                                     ((stripped_key & 0x8000000_8000000) >> 27);
        var subkey: u48 = 0;    
        for (0..48) |j| subkey = (subkey << 1) | @as(u1, @intCast((stripped_key >> PC2_FROM_56[j]) & 0x1));
        subkeys.*[i] = subkey;
    }
}

fn applyFeistelRound(right_half: u32, subkey: u48) u32 {
    var expanded_right_half: u48 = 0;
    for (0..48) |i| { // Expansion function:
        const row     = @divFloor(i, 6);
        const unbound = i - (row * 2);          //  0, 1..32, 33
        const bound   = @mod(unbound + 31, 32); // 31, 0..31, 0 
        const E:u5    = @intCast(31 - bound);   //  0, 31..0, 31 
        expanded_right_half = (expanded_right_half << 1) | ((right_half >> E) & 0x1);
    }
    const keyed_expansion: u48 = expanded_right_half ^ subkey;
    var sbox_output: u32 = 0;
    for (0..8) |s_box_idx| {
        const six_bit_chunk: u6 = @truncate(keyed_expansion >> @intCast(6 * ((S_TABLES.len - 1) - s_box_idx)));
        const row:   usize = (six_bit_chunk & 0b1) | ((six_bit_chunk & 0b10_0000) >> 4); // bit 0 and 5
        const col:   usize = (six_bit_chunk >> 1) & 0b1111;                              // bit  1...4
        const s_box: u32 = S_TABLES[s_box_idx][row][col];
        sbox_output |= s_box << @as(u5, @intCast(4 * ((S_TABLES.len - 1) - s_box_idx)));
    }
    var permuted: u32 = 0; 
    for (0..32) |i| permuted = (permuted << 1) | ((sbox_output >> P_FROM_32[i]) & 0x1);
    return permuted;
}

// Key Permuted Choice 1:
const PC1_col_0and4 = [7][2]u6{  // = 63 - (PC1 - 1)
    .{ 7, 39},
    .{ 6, 38},
    .{ 5, 37},
    .{ 4,  1},
    .{33,  2},
    .{34,  3},
    .{35, 36},
};

// Key Permuted Choice 2:
const PC2_FROM_56 = [_]u6{  // = 55 - (PC2 - 1)
    42, 39, 45, 32, 55, 51,
    53, 28, 41, 50, 35, 46,
    33, 37, 44, 52, 30, 48,
    40, 49, 29, 36, 43, 54,
    15,  4, 25, 19,  9,  1,
    26, 16,  5, 11, 23,  8,
    12,  7, 17,  0, 22,  3,
    10, 14,  6, 20, 27, 24,
};

// Initial Permutation:
const IP_first_col = [8]u3{ 6, 4, 2, 0, 7, 5, 3, 1};  // = 63 - (IP - 1)

// Inverse Initial Permutation:  (now includes the final left/right 32bit swap)
const IP_1_first_row = [8]u3{ 7, 3, 6, 2, 5, 1, 4, 0};  // = (63 - (IP_1 - 1)) / 8

// Permutation:
const P_FROM_32 = [_]u5 {  // = 31 - (P - 1)
    16, 25, 12, 11,  3, 20,  4, 15,
    31, 17,  9,  6, 27, 14,  1, 22,
    30, 24,  8, 18,  0,  5, 29, 23,
    13, 19,  2, 26, 10, 21, 28,  7,
};

// Substitution Boxes: [chunk][row][col]
const S_TABLES = [8][4][16]u4{
    .{
        .{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7}, 
        .{ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        .{ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        .{15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
    },.{    
        .{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10}, 
        .{ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        .{ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        .{13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
    },.{
        .{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8}, 
        .{13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        .{13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        .{ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
    },.{
        .{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15}, 
        .{13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        .{10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        .{ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
    },.{
        .{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9}, 
        .{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        .{ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        .{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
    },.{
        .{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11}, 
        .{10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        .{ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        .{ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
    },.{
        .{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1}, 
        .{13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        .{ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        .{ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
    },.{
        .{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7}, 
        .{ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        .{ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        .{ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
    }
};

test "DES Test Vectors" {
    // "19 Key data pairs which exercise every S-box entry."
    // U.S. National Bureau of Standards, 1977 (now NIST)
    // https://archive.org/details/validatingcorrec00gait/page/33/mode/1up
    const TEST_VECTORS = [_][3]u64{  //  key,  plaintext,  cipher
        .{0x7CA110454A1A6E57, 0x01A1D6D039776742, 0x690F5B0D9A26939B},
        .{0x0131D9619DC1376E, 0x5CD54CA83DEF57DA, 0x7A389D10354BD271},
        .{0x07A1133E4A0B2686, 0x0248D43806F67172, 0x868EBB51CAB4599A},
        .{0x3849674C2602319E, 0x51454B582DDF440A, 0x7178876E01F19B2A},
        .{0x04B915BA43FEB5B6, 0x42FD443059577FA2, 0xAF37FB421F8C4095},
        .{0x0113B970FD34F2CE, 0x059B5E0851CF143A, 0x86A560F10EC6D85B},
        .{0x0170F175468FB5E6, 0x0756D8E0774761D2, 0x0CD3DA020021DC09},
        .{0x43297FAD38E373FE, 0x762514B829BF486A, 0xEA676B2CB7DB2B7A},
        .{0x07A7137045DA2A16, 0x3BDD119049372802, 0xDFD64A815CAF1A0F},
        .{0x04689104C2FD3B2F, 0x26955F6835AF609A, 0x5C513C9C4886C088},
        .{0x37D06BB516CB7546, 0x164D5E404F275232, 0x0A2AEEAE3FF4AB77},
        .{0x1F08260D1AC2465E, 0x6B056E18759F5CCA, 0xEF1BF03E5DFA575A},
        .{0x584023641ABA6176, 0x004BD6EF09176062, 0x88BF0DB6D70DEE56},
        .{0x025816164629B007, 0x480D39006EE762F2, 0xA1F9915541020B56},
        .{0x49793EBC79B3258F, 0x437540C8698F3CFA, 0x6FBF1CAFCFFD0556},
        .{0x4FB05E1515AB73A7, 0x072D43A077075292, 0x2F22E49BAB7CA1AC},
        .{0x49E95D6D4CA229BF, 0x02FE55778117F12A, 0x5A6B612CC26CCE4A},
        .{0x018310DC409B26D6, 0x1D9D5C5018F728C2, 0x5F4C038ED12B2E41},
        .{0x1C587F1C13924FEF, 0x305532286D6F295A, 0x63FAC0D034D9F793}, 
    };

    for (TEST_VECTORS, 0..) |test_vector, i| {
        std.debug.print("test vector {}:\n", .{i});
        const key             = test_vector[0];
        const plaintext       = test_vector[1];
        const expected_cipher = test_vector[2];
        var block:     [8]u8  = [_]u8{0} ** 8;
        var subkeys:  [16]u48 = .{0} ** 16;

        // test encryption:
        std.mem.writeInt(u64, &block, plaintext, .big);
        init_encrypt(key, &subkeys);
        process_8bytes(&block, &subkeys);
        const encrypted_block: u64 = std.mem.readInt(u64, &block, .big);
        try std.testing.expect(encrypted_block == expected_cipher);

        // test decryption:
        std.mem.writeInt(u64, &block, encrypted_block, .big);
        init_decrypt(key, &subkeys);
        process_8bytes(&block, &subkeys);
        const decrypted_block: u64 = std.mem.readInt(u64, &block, .big);
        try std.testing.expect(decrypted_block == plaintext);
    }
}

