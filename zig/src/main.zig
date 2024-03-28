const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const native_endian = builtin.cpu.arch.endian();

/// Derive-Key-AES and Double-Nonce-Derive-Key-AES nonce extension mechanisms.
///
/// Extends the lifeftime of a cipher's secret key by deriving a new key from it and a nonce.
///
/// ---
///
/// Usage with AES-128 (Derive-Key-AES-GCM):
///
/// ```zig
/// const encryption_key = nonceExtenstion(std.crypto.core.aes.Aes128, key, nonce);
/// const zero_nonce = [_]u8{0} ** Aes128Gcm.nonce_length;
/// Aes128Gcm.encrypt(
///     encryption_key, zero_nonce, plaintext, aad, ciphertext, tag
/// );
/// ```
///
/// The nonce can be any length up to 120 bits (15 bytes).
///
/// This significantly extends the key lifetime and improves the security bounds of AES-GCM.
///
/// ---
///
/// Usage with AES-256 (Double-Nonce-Derive-Key-AES-GCM):
///
/// ```zig
/// const encryption_key = nonceExtenstion(std.crypto.core.aes.Aes256, key, nonce);
/// const zero_nonce = [_]u8{0} ** Aes256Gcm.nonce_length;
/// Aes256Gcm.encrypt(
///     encryption_key, zero_nonce, plaintext, aad, ciphertext, tag
/// );
/// ```
///
/// The nonce can be any length up to 232 bits, but for practical purposes, 192 bits (24 bytes)
/// is recommended.
///
/// This allows the key to be reused without any practical limits on the number of messages,
/// and nonce can be generated randomly without any risk of collision.
///
/// `BlockCipher`: the block cipher type. Usually `std.crypto.core.aes.Aes128` or `std.crypto.core.aes.Aes256`.
/// `key`: the secret key to derive from.
/// `nonce`: the nonce to derive with.
///
/// Returns the derived key, suitable for the given block cipher.
pub fn nonceExtension(comptime BlockCipher: type, key: [BlockCipher.key_bits / 8]u8, nonce: []const u8) [BlockCipher.key_bits / 8]u8 {
    std.debug.assert(BlockCipher.key_bits % 8 == 0); // Key size is not a multiple of 8
    const key_length = BlockCipher.key_bits / 8;
    const block_length = BlockCipher.block.block_length;
    const nonce_length = nonce.len;

    if (key_length < block_length) {
        @compileError("Nonce extension mechanism is incompatible with that block cipher");
    }
    if (key_length % BlockCipher.block.block_length != 0) {
        @compileError("Key size is not a multiple of the block size");
    }
    const key_blocks = key_length / BlockCipher.block.block_length;

    const ks = BlockCipher.initEnc(key);
    var dk: [key_length]u8 = undefined;

    if (key_blocks == 1) {
        std.debug.assert(nonce_length <= block_length - 1); // Key size is too short for that nonce size
        var blocks = [_]u8{0} ** (3 * block_length);
        inline for (0..3) |i| {
            var block = blocks[i * block_length ..];
            @memcpy(block[0..nonce.len], nonce);
            block[block_length - 1] = i;
        }
        ks.encryptWide(blocks.len / block_length, &blocks, &blocks);
        mem.writeInt(
            u128,
            dk[0..],
            mem.readInt(u128, blocks[0 * block_length ..][0..block_length], native_endian) ^
                mem.readInt(u128, blocks[1 * block_length ..][0..block_length], native_endian) ^
                mem.readInt(u128, blocks[2 * block_length ..][0..block_length], native_endian),
            native_endian,
        );
    } else if (key_blocks == 2) {
        std.debug.assert(nonce_length <= 2 * block_length - 1); // Key size is too short for that double-nonce size
        const n0 = nonce[0 .. nonce_length / 2];
        const n1 = nonce[nonce_length / 2 ..];
        var blocks = [_]u8{0} ** (2 * 3 * block_length);
        inline for (0..3) |i| {
            var block0 = blocks[i * block_length ..];
            var block1 = blocks[(i + 3) * block_length ..];
            @memcpy(block0[0..n0.len], n0);
            block0[block_length - 1] = 0 + i * 2;
            @memcpy(block1[0..n1.len], n1);
            block1[block_length - 1] = 1 + i * 2;
        }
        ks.encryptWide(blocks.len / block_length, &blocks, &blocks);
        mem.writeInt(
            u128,
            dk[0 .. dk.len / 2],
            mem.readInt(u128, blocks[0 * block_length ..][0..block_length], native_endian) ^
                mem.readInt(u128, blocks[1 * block_length ..][0..block_length], native_endian) ^
                mem.readInt(u128, blocks[2 * block_length ..][0..block_length], native_endian),
            native_endian,
        );
        mem.writeInt(
            u128,
            dk[dk.len / 2 ..],
            mem.readInt(u128, blocks[3 * block_length ..][0..block_length], native_endian) ^
                mem.readInt(u128, blocks[4 * block_length ..][0..block_length], native_endian) ^
                mem.readInt(u128, blocks[5 * block_length ..][0..block_length], native_endian),
            native_endian,
        );
    } else {
        @compileError("Nonce extension mechanism is incompatible with that key size");
    }
    return dk;
}

pub const XAes256Gcm = struct {
    pub const key_length = 32;
    const nonce_length = 24;
    const tag_length = 16;
    pub const ciphertext_overhead_length = tag_length + nonce_length;

    /// Generate a random AES256 key.
    pub fn keygen() [key_length]u8 {
        var key: [key_length]u8 = undefined;
        std.crypto.random.bytes(&key);
        return key;
    }

    /// Encrypt a message with Double-Nonce-Derive-Key-AES256-GCM.
    /// The (automatically generated) nonce and tag are automatically included in the output.
    /// The ciphertext buffer length must be `plaintext.len + XAes256Gcm.overheader_length`.
    pub fn encrypt(
        key: [key_length]u8,
        ciphertext: []u8,
        plaintext: []const u8,
        associated_data: ?[]const u8,
    ) void {
        std.debug.assert(ciphertext.len == plaintext.len + ciphertext_overhead_length); // Ciphertext buffer length must be plaintext.len + XAes256Gcm.overheader_length
        const nonce = ciphertext[0..nonce_length];
        const c = ciphertext[nonce_length..][0..plaintext.len];
        const tag = ciphertext[ciphertext.len - tag_length ..][0..tag_length];
        std.crypto.random.bytes(nonce);
        const dk = nonceExtension(std.crypto.core.aes.Aes256, key, nonce);
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(
            c,
            tag,
            plaintext,
            associated_data orelse "",
            [_]u8{0} ** 12,
            dk,
        );
    }

    /// Decrypt a message with Double-Nonce-Derive-Key-AES256-GCM.
    /// The plaintext buffer length must be `ciphertext.len - XAes256Gcm.overheader_length`.
    pub fn decrypt(
        key: [key_length]u8,
        plaintext: []u8,
        ciphertext: []const u8,
        associated_data: ?[]const u8,
    ) std.crypto.errors.AuthenticationError!void {
        std.debug.assert(ciphertext.len == plaintext.len + ciphertext_overhead_length); // Plaintext buffer length must be ciphertext.len - XAes256Gcm.overheader_length
        if (ciphertext.len < ciphertext_overhead_length) {
            return error.AuthenticationFailed;
        }
        const nonce = ciphertext[0..nonce_length];
        const c = ciphertext[nonce_length..][0..plaintext.len];
        const tag = ciphertext[ciphertext.len - tag_length ..][0..tag_length].*;
        const dk = nonceExtension(std.crypto.core.aes.Aes256, key, nonce);
        try std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
            plaintext,
            c,
            tag,
            associated_data orelse "",
            [_]u8{0} ** 12,
            dk,
        );
    }
};

const aes = std.crypto.core.aes;
const testing = std.testing;

test "nonce-derive-aes128" {
    const nonce_hex = "0123456789abcdeffedcba98765432"; // 120-bit nonce
    const key_hex = "0123456789abcdeffedcba9876543210"; // 128-bit key
    var nonce: [nonce_hex.len / 2]u8 = undefined;
    var key: [key_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const dk = nonceExtension(aes.Aes128, key, &nonce); // 128-bit derived key
    const expected_dk_hex = "5f52f039f349f01c7969019c0d19878d";
    try testing.expectEqualSlices(u8, expected_dk_hex, &std.fmt.bytesToHex(dk, .lower));
}

test "double-nonce-derive-aes256" {
    const nonce_hex = "0123456789abcdeffedcba987654321089abcdeffedcba98"; // 192-bit nonce
    const key_hex = "0123456789abcdeffedcba9876543210123456789abcdeffedcba9876543210f"; // 256-bit key
    var nonce: [nonce_hex.len / 2]u8 = undefined;
    var key: [key_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&key, key_hex);
    const dk = nonceExtension(aes.Aes256, key, &nonce); // 256-bit derived key
    const expected_dk_hex = "545e7f545b925d46212c50e7df5ad33b8e650482a8e6476899ed6bb6f418e6d0";
    try testing.expectEqualSlices(u8, expected_dk_hex, &std.fmt.bytesToHex(dk, .lower));
}

test "double-nonce-derive-aes256-gcm" {
    const key = XAes256Gcm.keygen();
    const plaintext = "Hello, world!";
    var ciphertext: [plaintext.len + XAes256Gcm.ciphertext_overhead_length]u8 = undefined;
    XAes256Gcm.encrypt(key, &ciphertext, plaintext, null);
    var decrypted: [plaintext.len]u8 = undefined;
    try XAes256Gcm.decrypt(key, &decrypted, &ciphertext, null);
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}
