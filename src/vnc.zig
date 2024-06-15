//!
//! Links:
//! - https://datatracker.ietf.org/doc/html/rfc6143
//! - https://en.wikipedia.org/wiki/RFB_protocol
//!
const std = @import("std");
const network = @import("network");

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

/// RFB pixel format / color encoding.
///
/// See also: https://datatracker.ietf.org/doc/html/rfc6143#section-7.4
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

    /// Bits-per-pixel is the number of bits used for each pixel value on the
    /// wire. This must be greater than or equal to the depth.
    bpp: u8,

    /// The number of useful bits in the pixel value. Currently bits-per-pixel must be 8, 16, or 32.
    depth: u8,

    /// Big-endian-flag is non-zero (true) if multi- byte pixels are interpreted as big endian.
    big_endian: u8,

    /// If true-color-flag is non-zero (true), then the last six items
    /// specify how to extract the red, green, and blue intensities from the
    /// pixel value.
    true_color: u8,
    // Red-max is the maximum red value and must be 2^N - 1, where N is the number of bits used for red.
    red_max: u16,
    green_max: u16,
    blue_max: u16,
    /// Red-shift is the number of shifts needed to get the red value in a pixel to the least significant bit.
    red_shift: u8,
    green_shift: u8,
    blue_shift: u8,

    pub fn serialize(self: PixelFormat, writer: anytype) !void {
        try writer.writeInt(u8, self.bpp, .big);
        try writer.writeInt(u8, self.depth, .big);
        try writer.writeInt(u8, self.big_endian, .big);
        try writer.writeInt(u8, self.true_color, .big);
        try writer.writeInt(u16, self.red_max, .big);
        try writer.writeInt(u16, self.green_max, .big);
        try writer.writeInt(u16, self.blue_max, .big);
        try writer.writeInt(u8, self.red_shift, .big);
        try writer.writeInt(u8, self.green_shift, .big);
        try writer.writeInt(u8, self.blue_shift, .big);
        try writer.writeAll("\x00\x00\x00"); // padding
    }

    pub fn deserialize(reader: anytype) !PixelFormat {
        const pf = PixelFormat{
            .bpp = try reader.readInt(u8, .big),
            .depth = try reader.readInt(u8, .big),
            .big_endian = try reader.readInt(u8, .big),
            .true_color = try reader.readInt(u8, .big),
            .red_max = try reader.readInt(u16, .big),
            .green_max = try reader.readInt(u16, .big),
            .blue_max = try reader.readInt(u16, .big),
            .red_shift = try reader.readInt(u8, .big),
            .green_shift = try reader.readInt(u8, .big),
            .blue_shift = try reader.readInt(u8, .big),
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

        const endianess: std.builtin.Endian = switch (pf.big_endian) {
            0 => .little,
            else => .big,
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

    pub fn format(pf: PixelFormat, fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try writer.print(
            \\PixelFormat({} bpp, {} )
        , .{
            pf.bpp,
            pf.depth,
            // pf.big_endian,
            // pf.true_color,
            // pf.red_max,
            // pf.green_max,
            // pf.blue_max,
            // pf.red_shift,
            // pf.green_shift,
            // pf.blue_shift,
        });
    }
};

pub const ServerProperties = struct {
    /// The name of the desktop served by this server.
    desktop_name: []const u8,

    screen_width: u16,
    screen_height: u16,

    /// Server-pixel-format specifies the server's natural pixel format.
    /// This pixel format will be used unless the client requests a different
    /// format using the SetPixelFormat message (Section 7.5.1).
    pixel_format: PixelFormat = PixelFormat.bgrx8888,
};

pub const Server = struct {
    socket: network.Socket,
    temp_memory: std.ArrayListAligned(u8, 16),

    // public api:

    protocol_version: ProtocolVersion,
    shared_connection: bool,
    pixel_format: PixelFormat,

    pub fn open(allocator: std.mem.Allocator, sock: network.Socket, properties: ServerProperties) !Server {
        errdefer sock.close();

        const desktop_name_len = std.math.cast(u32, properties.desktop_name.len) orelse return error.Overflow;

        var writer = sock.writer();
        var reader = sock.reader();

        // Initial handshake
        const protocol_version = blk: {
            try writer.writeAll("RFB 003.008\n"); // RFB Version 3.8

            var handshake: [12]u8 = undefined;
            try reader.readNoEof(&handshake);

            break :blk try ProtocolVersion.parse(handshake);
        };

        // Security handshake. We are insecure.
        {
            try writer.writeByte(1); // number of types
            try writer.writeByte(@intFromEnum(Security.none)); // "no security"

            const selected_security = std.meta.intToEnum(Security, try reader.readByte()) catch return error.ProtocolMismatch;

            std.debug.print("client security: {}\n", .{selected_security});

            const authentication_good = switch (selected_security) {
                .none => true,
                .vnc_authentication => blk: {
                    var challenge: [16]u8 = undefined;
                    std.crypto.random.bytes(&challenge);
                    try writer.writeAll(&challenge);

                    // The client encrypts the challenge with DES, using a password supplied
                    // by the user as the key. To form the key, the password is truncated
                    // to eight characters, or padded with null bytes on the right. The
                    // client then sends the resulting 16-byte response:

                    var response: [16]u8 = undefined;
                    try reader.readNoEof(&response);

                    // TODO: Implement a proper DES verification

                    break :blk std.mem.eql(u8, &response, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
                },
                else => return error.ProtocolMismatch,
            };

            if (authentication_good) {
                try writer.writeInt(u32, 0, .big); // handshake OK
            } else {
                try writer.writeInt(u32, 1, .big); // handshake failed

                const error_message = "Hello World!";

                try writer.writeInt(u32, error_message.len, .big);
                try writer.writeAll(error_message);

                // We failed to handle the client connection, but
                // this is a "successful" state.
                return error.AuthenticationFailed;
            }
        }

        // Initialization phase
        const shared_connection = blk: {
            const shared_flag = try reader.readByte(); // 0 => disconnect others, 1 => share with others

            try writer.writeInt(u16, properties.screen_width, .big); // width
            try writer.writeInt(u16, properties.screen_height, .big); // height
            try properties.pixel_format.serialize(writer); // pixel format, 16 byte

            try writer.writeInt(u32, desktop_name_len, .big); // virtual desktop name len
            try writer.writeAll(properties.desktop_name); // virtual desktop name bytes

            break :blk (shared_flag != 0);
        };

        return Server{
            .socket = sock,
            .temp_memory = std.ArrayListAligned(u8, 16).init(allocator),

            .protocol_version = protocol_version,
            .shared_connection = shared_connection,
            .pixel_format = properties.pixel_format,
        };
    }

    pub fn close(self: *Server) void {
        self.temp_memory.deinit();
        self.socket.close();
        self.* = undefined;
    }

    pub fn waitEvent(self: *Server) !?ClientEvent {
        var reader = self.socket.reader();

        const message_byte = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => return null,
            else => |e| return e,
        };

        const message_type = std.meta.intToEnum(ClientMessageType, message_byte) catch return error.ProtocolViolation;
        switch (message_type) {
            .set_pixel_format => {
                var padding: [3]u8 = undefined;
                try reader.readNoEof(&padding);

                const pf = try PixelFormat.deserialize(reader);
                self.pixel_format = pf; // update the current pixel format
                return ClientEvent{ .set_pixel_format = pf };
            },
            .set_encodings => {
                var padding: [1]u8 = undefined;
                try reader.readNoEof(&padding);

                const num_encodings = try reader.readInt(u16, .big);

                try self.temp_memory.resize(@sizeOf(Encoding) * num_encodings);

                const encodings = @as([*]Encoding, @ptrCast(self.temp_memory.items.ptr))[0..num_encodings];

                var i: usize = 0;
                while (i < num_encodings) : (i += 1) {
                    encodings[i] = @as(Encoding, @enumFromInt(try reader.readInt(i32, .big)));
                }

                return ClientEvent{ .set_encodings = encodings };
            },
            .framebuffer_update_request => {
                const incremental = try reader.readByte();
                const x_pos = try reader.readInt(u16, .big);
                const y_pos = try reader.readInt(u16, .big);
                const width = try reader.readInt(u16, .big);
                const height = try reader.readInt(u16, .big);

                return ClientEvent{
                    .framebuffer_update_request = .{
                        .incremental = (incremental != 0),
                        .x = x_pos,
                        .y = y_pos,
                        .width = width,
                        .height = height,
                    },
                };
            },
            .key_event => {
                const down_flag = try reader.readByte();

                var padding: [2]u8 = undefined;
                try reader.readNoEof(&padding);

                const key: Key = @enumFromInt(try reader.readInt(u32, .big));

                return ClientEvent{
                    .key_event = .{ .key = key, .down = (down_flag != 0) },
                };
            },
            .pointer_event => {
                const button_mask = try reader.readByte();
                const x_pos = try reader.readInt(u16, .big);
                const y_pos = try reader.readInt(u16, .big);

                return ClientEvent{
                    .pointer_event = .{ .x = x_pos, .y = y_pos, .buttons = button_mask },
                };
            },
            .client_cut_text => {
                var padding: [3]u8 = undefined;
                try reader.readNoEof(&padding);

                const msg_length = try reader.readInt(u32, .big);

                try self.temp_memory.resize(msg_length);

                try reader.readNoEof(self.temp_memory.items);

                return ClientEvent{
                    .client_cut_text = self.temp_memory.items,
                };
            },
            // else => {
            //     std.debug.print("unhandled message type: {}\n", .{message_type});

            //     var seq: [4096]u8 = undefined;
            //     const len = try reader.read(&seq);
            //     if (len == 0)
            //         break;

            //     std.debug.print("received: {}\n", .{
            //         std.fmt.fmtSliceEscapeUpper(seq[0..len]),
            //     });
            // },
        }
    }

    pub fn sendFramebufferUpdate(self: *Server, rectangles: []const UpdateRectangle) !void {
        const num_rects = std.math.cast(u16, rectangles.len) orelse return error.Overflow;

        var buffered_writer = std.io.bufferedWriter(self.socket.writer());
        const writer = buffered_writer.writer();
        try writer.writeByte(@intFromEnum(ServerMessageType.framebuffer_update));
        try writer.writeByte(0); // padding

        try writer.writeInt(u16, num_rects, .big);

        for (rectangles) |rect| {
            try writer.writeInt(u16, rect.x, .big);
            try writer.writeInt(u16, rect.y, .big);
            try writer.writeInt(u16, rect.width, .big);
            try writer.writeInt(u16, rect.height, .big);
            try writer.writeInt(i32, @intFromEnum(rect.encoding), .big);
            try writer.writeAll(rect.data);
        }

        try buffered_writer.flush();
    }

    /// Changes entries in the clients color map.
    /// - `first` is the first color entry to change.
    /// - `colors` is a slice of colors that will be written to the client color map at the offset `first`.
    pub fn sendSetColorMapEntries(self: *Server, first: u16, colors: []const Color) !void {
        const color_count = try std.math.cast(u16, colors.len);

        var writer = self.socket.writer();
        try writer.writeByte(@intFromEnum(ServerMessageType.set_color_map_entries));
        try writer.writeByte(0); // padding

        try writer.writeInt(u16, first, .big);
        try writer.writeInt(u16, color_count, .big);

        for (colors) |c| {
            try writer.writeInt(u16, @intFromFloat(std.math.maxInt(u16) * std.math.clamp(c.r, 0.0, 1.0)), .big);
            try writer.writeInt(u16, @intFromFloat(std.math.maxInt(u16) * std.math.clamp(c.g, 0.0, 1.0)), .big);
            try writer.writeInt(u16, @intFromFloat(std.math.maxInt(u16) * std.math.clamp(c.b, 0.0, 1.0)), .big);
        }
    }

    /// Rings a signal on the viewer if possible.
    pub fn sendBell(self: *Server) !void {
        var writer = self.socket.writer();
        try writer.writeByte(@intFromEnum(ServerMessageType.bell));
    }

    /// Sets the new clipboard content of the viewer.
    /// - `text` is the ISO 8859-1 (Latin-1) encoded text.
    pub fn sendServerCutText(self: *Server, text: []const u8) !void {
        const length = std.math.cast(u32, text.len) orelse return error.Overflow;

        var writer = self.socket.writer();
        try writer.writeByte(@intFromEnum(ServerMessageType.server_cut_text));
        try writer.writeByte(0); // padding
        try writer.writeByte(0); // padding
        try writer.writeByte(0); // padding
        try writer.writeInt(u32, length, .big);
        try writer.writeAll(text);
    }
};

/// https://datatracker.ietf.org/doc/html/rfc6143#section-7.6.1
pub const UpdateRectangle = struct {
    x: u16,
    y: u16,
    width: u16,
    height: u16,
    encoding: Encoding,
    data: []const u8,
};

pub const ClientEvent = union(ClientMessageType) {
    /// https://datatracker.ietf.org/doc/html/rfc6143#section-7.5.1
    set_pixel_format: PixelFormat,

    /// https://datatracker.ietf.org/doc/html/rfc6143#section-7.5.2
    set_encodings: []const Encoding,

    /// https://datatracker.ietf.org/doc/html/rfc6143#section-7.5.3
    framebuffer_update_request: FramebufferUpdateRequest,

    /// https://datatracker.ietf.org/doc/html/rfc6143#section-7.5.4
    key_event: KeyEvent,

    /// https://datatracker.ietf.org/doc/html/rfc6143#section-7.5.5
    pointer_event: PointerEvent,

    /// https://datatracker.ietf.org/doc/html/rfc6143#section-7.5.6
    client_cut_text: []const u8,

    /// A FramebufferUpdateRequest message notifies the server that the
    /// client is interested in the area of the framebuffer specified by
    /// x-position, y-position, width, and height. The server usually
    /// responds to a FramebufferUpdateRequest by sending a
    /// FramebufferUpdate. A single FramebufferUpdate may be sent in reply
    /// to several FramebufferUpdateRequests.
    ///
    /// The server assumes that the client keeps a copy of all parts of the
    /// framebuffer in which it is interested.  This means that normally the
    /// server only needs to send incremental updates to the client.
    ///
    /// If the client has lost the contents of a particular area that it
    /// needs, then the client sends a FramebufferUpdateRequest with
    /// incremental set to zero (false).  This requests that the server send
    /// the entire contents of the specified area as soon as possible.  The
    /// area will not be updated using the CopyRect encoding.
    ///
    /// If the client has not lost any contents of the area in which it is
    /// interested, then it sends a FramebufferUpdateRequest with incremental
    /// set to non-zero (true). If and when there are changes to the
    /// specified area of the framebuffer, the server will send a
    /// FramebufferUpdate.  Note that there may be an indefinite period
    /// between the FramebufferUpdateRequest and the FramebufferUpdate.
    ///
    /// In the case of a fast client, the client may want to regulate the
    /// rate at which it sends incremental FramebufferUpdateRequests to avoid
    /// excessive network traffic.
    pub const FramebufferUpdateRequest = struct {
        incremental: bool,
        x: u16,
        y: u16,
        width: u16,
        height: u16,
    };

    pub const KeyEvent = struct {
        key: Key,
        down: bool,
    };

    pub const PointerEvent = struct {
        x: u16,
        y: u16,
        buttons: u8,
    };
};
