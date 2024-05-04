const std = @import("std");

pub const Color = struct {
    r: f32,
    g: f32,
    b: f32,
};

pub const ProtocolVersion = struct {
    major: u8,
    minor: u8,

    pub fn parse(handshake: [12]u8) !ProtocolVersion {
        if (!std.mem.eql(u8, handshake[0..4], "RFB "))
            return error.ProtocolMismatch;
        if (handshake[7] != '.')
            return error.ProtocolMismatch;
        if (handshake[11] != '\n')
            return error.ProtocolMismatch;

        const major_version = std.fmt.parseInt(u8, handshake[4..7], 10) catch return error.ProtocolMismatch;
        const minor_version = std.fmt.parseInt(u8, handshake[8..11], 10) catch return error.ProtocolMismatch;

        return ProtocolVersion{ .major = major_version, .minor = minor_version };
    }
};

pub const Security = enum(u8) {
    invalid = 0,
    none = 1,
    vnc_authentication = 2,
};

pub const ClientMessageType = enum(u8) {
    set_pixel_format = 0,
    set_encodings = 2,
    framebuffer_update_request = 3,
    key_event = 4,
    pointer_event = 5,
    client_cut_text = 6,
};

pub const ServerMessageType = enum(u8) {
    framebuffer_update = 0,
    set_color_map_entries = 1,
    bell = 2,
    server_cut_text = 3,
};

pub const Key = enum(u32) {
    // For most ordinary keys, the keysym is the same as the corresponding
    // ASCII value. For full details, see [XLIBREF] or see the header file
    // <X11/keysymdef.h> in the X Window System distribution. Some other
    // common keys are:
    back_space = 0xff08,
    tab = 0xff09,
    @"return" = 0xff0d,
    escape = 0xff1b,
    insert = 0xff63,
    delete = 0xffff,
    home = 0xff50,
    end = 0xff57,
    page_up = 0xff55,
    page_down = 0xff56,
    left = 0xff51,
    up = 0xff52,
    right = 0xff53,
    down = 0xff54,
    f1 = 0xffbe,
    f2 = 0xffbf,
    f3 = 0xffc0,
    f4 = 0xffc1,
    f5 = 0xffc2,
    f6 = 0xffc3,
    f7 = 0xffc4,
    f8 = 0xffc5,
    f9 = 0xffc6,
    f10 = 0xffc7,
    f11 = 0xffc8,
    f12 = 0xffc9,
    shift_left = 0xffe1,
    shift_right = 0xffe2,
    control_left = 0xffe3,
    control_right = 0xffe4,
    meta_left = 0xffe7,
    meta_right = 0xffe8,
    alt_left = 0xffe9,
    alt_right = 0xffea,

    _,
};

pub const Encoding = enum(i32) {
    raw = 0,
    copy_rect = 1,
    rre = 2,
    hextile = 5,
    trle = 15,
    zrle = 16,
    cursor_pseudo_encoding = -239,
    desktop_size_pseudo_encoding = -223,
    _,
};

pub const PixelFormat = struct {
    pub const bgrx8888 = PixelFormat{
        .bpp = 32,
        .depth = 24,
        .big_endian = 0,
        .true_color = 1,
        .red_max = 255,
        .green_max = 255,
        .blue_max = 255,
        .red_shift = 16,
        .green_shift = 8,
        .blue_shift = 0,
    };

    bpp: u8,
    depth: u8,
    big_endian: u8,
    true_color: u8,
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,

    pub fn serialize(self: PixelFormat, writer: anytype) !void {
        try writer.writeIntBig(u8, self.bpp);
        try writer.writeIntBig(u8, self.depth);
        try writer.writeIntBig(u8, self.big_endian);
        try writer.writeIntBig(u8, self.true_color);
        try writer.writeIntBig(u16, self.red_max);
        try writer.writeIntBig(u16, self.green_max);
        try writer.writeIntBig(u16, self.blue_max);
        try writer.writeIntBig(u8, self.red_shift);
        try writer.writeIntBig(u8, self.green_shift);
        try writer.writeIntBig(u8, self.blue_shift);
        try writer.writeAll("\x00\x00\x00"); // padding
    }

    pub fn deserialize(reader: anytype) !PixelFormat {
        var pf = PixelFormat{
            .bpp = try reader.readIntBig(u8),
            .depth = try reader.readIntBig(u8),
            .big_endian = try reader.readIntBig(u8),
            .true_color = try reader.readIntBig(u8),
            .red_max = try reader.readIntBig(u16),
            .green_max = try reader.readIntBig(u16),
            .blue_max = try reader.readIntBig(u16),
            .red_shift = try reader.readIntBig(u8),
            .green_shift = try reader.readIntBig(u8),
            .blue_shift = try reader.readIntBig(u8),
        };
        var padding: [3]u8 = undefined;
        try reader.readNoEof(&padding); // padding
        return pf;
    }

    pub fn encode(pf: PixelFormat, buf: *[8]u8, color: Color) []u8 {
        var encoded: u64 = 0;

        if (pf.true_color != 0) {
            encoded |= @as(u64, @intFromFloat(@as(f32, @floatFromInt(pf.red_max)) * color.r)) << @as(u6, @truncate(pf.red_shift));
            encoded |= @as(u64, @intFromFloat(@as(f32, @floatFromInt(pf.green_max)) * color.g)) << @as(u6, @truncate(pf.green_shift));
            encoded |= @as(u64, @intFromFloat(@as(f32, @floatFromInt(pf.blue_max)) * color.b)) << @as(u6, @truncate(pf.blue_shift));
        } else {
            @panic("indexed color encoding not implemented yet");
        }

        const endianess = switch (pf.big_endian) {
            0 => std.builtin.Endian.Little,
            else => std.builtin.Endian.Big,
        };

        switch (pf.bpp) {
            8 => {
                const part = buf[0..1];
                std.mem.writeInt(u8, part, @as(u8, @truncate(encoded)), endianess);
                return part;
            },
            16 => {
                const part = buf[0..2];
                std.mem.writeInt(u16, part, @as(u16, @truncate(encoded)), endianess);
                return part;
            },
            24 => {
                const part = buf[0..3];
                std.mem.writeInt(u24, part, @as(u24, @truncate(encoded)), endianess);
                return part;
            },
            32 => {
                const part = buf[0..4];
                std.mem.writeInt(u32, part, @as(u32, @truncate(encoded)), endianess);
                return part;
            },
            64 => {
                const part = buf[0..8];
                std.mem.writeInt(u64, part, @as(u64, @truncate(encoded)), endianess);
                return part;
            },
            else => return buf[0..0],
        }
    }

    pub fn decode(pf: PixelFormat, encoded: []const u8) Color {
        _ = pf;
        _ = encoded;
    }
};
