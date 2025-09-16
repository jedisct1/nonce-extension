const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const aes = std.crypto.core.aes;
const aead = std.crypto.aead.aes_gcm;

/// DNDK-GCM: Double Nonce Derive Key AES-GCM
/// As specified in https://datatracker.ietf.org/doc/draft-gueron-cfrg-dndkgcm-03/
pub const DndkGcm = struct {
    pub const root_key_length = 32;
    pub const max_nonce_length = 27;
    pub const min_nonce_length = 12;
    pub const tag_length = 16;
    pub const key_commit_length = 32;

    /// Configuration option for key commitment
    pub const Config = enum(u1) {
        no_key_commitment = 0,
        with_key_commitment = 1,
    };

    /// Result of the Derive function
    pub const DeriveResult = struct {
        derived_key: [32]u8,
        key_commit: ?[32]u8,
        ntail: [12]u8,
    };

    /// Calculate ConfigByte based on KC_Choice and nonce length
    fn calcConfigByte(kc_choice: Config, nonce_len: usize) u8 {
        const kc_val: u8 = @intFromEnum(kc_choice);
        return 128 * kc_val + 8 * @as(u8, @intCast(nonce_len - 12));
    }

    /// Derive function as specified in the DNDK-GCM draft
    pub fn derive(root_key: [root_key_length]u8, nonce: []const u8, config: Config) DeriveResult {
        std.debug.assert(nonce.len >= min_nonce_length and nonce.len <= max_nonce_length);

        // Step 1: Pad nonce to 27 bytes
        var npadded: [27]u8 = [_]u8{0} ** 27;
        @memcpy(npadded[0..nonce.len], nonce);

        // Step 2: Split into NHead (15 bytes) and NTail (12 bytes)
        const nhead = npadded[0..15];
        const ntail = npadded[15..27];

        // Step 3: Calculate ConfigByte
        const config_byte = calcConfigByte(config, nonce.len);

        // Step 4: Initialize AES-256 with root key
        const ctx = aes.Aes256.initEnc(root_key);

        // Step 5 & 6: Generate and encrypt blocks using encryptWide for better performance
        var x0: [16]u8 = undefined;
        var x1: [16]u8 = undefined;
        var x2: [16]u8 = undefined;
        var x3: [16]u8 = undefined;
        var x4: [16]u8 = undefined;

        if (config == .with_key_commitment) {
            // Prepare 5 blocks for parallel encryption
            var blocks: [5][16]u8 = undefined;
            inline for (0..5) |i| {
                @memcpy(blocks[i][0..15], nhead);
                blocks[i][15] = config_byte + @as(u8, @intCast(i));
            }

            // Encrypt all 5 blocks in parallel
            var x_blocks: [5][16]u8 = undefined;
            ctx.encryptWide(5, @as(*[5 * 16]u8, @ptrCast(&x_blocks)), @as(*const [5 * 16]u8, @ptrCast(&blocks)));

            x0 = x_blocks[0];
            x1 = x_blocks[1];
            x2 = x_blocks[2];
            x3 = x_blocks[3];
            x4 = x_blocks[4];
        } else {
            // Prepare 3 blocks for parallel encryption
            var blocks: [3][16]u8 = undefined;
            inline for (0..3) |i| {
                @memcpy(blocks[i][0..15], nhead);
                blocks[i][15] = config_byte + @as(u8, @intCast(i));
            }

            // Encrypt all 3 blocks in parallel
            var x_blocks: [3][16]u8 = undefined;
            ctx.encryptWide(3, @as(*[3 * 16]u8, @ptrCast(&x_blocks)), @as(*const [3 * 16]u8, @ptrCast(&blocks)));

            x0 = x_blocks[0];
            x1 = x_blocks[1];
            x2 = x_blocks[2];
        }

        // Step 7: Compute Y values via XOR
        var y1: [16]u8 = undefined;
        var y2: [16]u8 = undefined;
        var y3: [16]u8 = undefined;
        var y4: [16]u8 = undefined;

        for (0..16) |i| {
            y1[i] = x1[i] ^ x0[i];
            y2[i] = x2[i] ^ x0[i];
            if (config == .with_key_commitment) {
                y3[i] = x3[i] ^ x0[i];
                y4[i] = x4[i] ^ x0[i];
            }
        }

        // Step 8: Assemble derived key and key commitment
        var result: DeriveResult = undefined;
        @memcpy(result.derived_key[0..16], &y1);
        @memcpy(result.derived_key[16..32], &y2);
        @memcpy(&result.ntail, ntail);

        if (config == .with_key_commitment) {
            var key_commit: [32]u8 = undefined;
            @memcpy(key_commit[0..16], &y3);
            @memcpy(key_commit[16..32], &y4);
            result.key_commit = key_commit;
        } else {
            result.key_commit = null;
        }

        return result;
    }

    /// Encrypt using DNDK-GCM
    pub fn encrypt(
        root_key: [root_key_length]u8,
        nonce: []const u8,
        plaintext: []const u8,
        aad: []const u8,
        ciphertext: []u8,
        tag: *[tag_length]u8,
        config: Config,
    ) ?[key_commit_length]u8 {
        const derive_result = derive(root_key, nonce, config);

        // Use NTail as the GCM nonce
        aead.Aes256Gcm.encrypt(
            ciphertext,
            tag,
            plaintext,
            aad,
            derive_result.ntail,
            derive_result.derived_key,
        );

        return derive_result.key_commit;
    }

    /// Decrypt using DNDK-GCM
    pub fn decrypt(
        root_key: [root_key_length]u8,
        nonce: []const u8,
        ciphertext: []const u8,
        aad: []const u8,
        tag: [tag_length]u8,
        plaintext: []u8,
        config: Config,
        expected_key_commit: ?[key_commit_length]u8,
    ) !void {
        const derive_result = derive(root_key, nonce, config);

        // Check key commitment if provided
        if (expected_key_commit) |expected| {
            if (derive_result.key_commit) |actual| {
                if (!std.crypto.timing_safe.eql([32]u8, expected, actual)) {
                    return error.AuthenticationFailed;
                }
            } else {
                return error.AuthenticationFailed;
            }
        }

        // Use NTail as the GCM nonce
        try aead.Aes256Gcm.decrypt(
            plaintext,
            ciphertext,
            tag,
            aad,
            derive_result.ntail,
            derive_result.derived_key,
        );
    }
};

const testing = std.testing;

test "DNDK-GCM test vector A.1 (LN=24, with key commitment)" {
    const root_key_hex = "0100000000000000000000000000000000000000000000000000000000000000";
    const nonce_hex = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const aad_hex = "0100000011";
    const plaintext_hex = "11000001";
    const expected_ciphertext_hex = "8eee8a4b";
    const expected_tag_hex = "8a1c8d0ceb7e07e3c834cafe75aa001f";
    const expected_dk_hex = "3d1480ee39a968d581d16a578bdaf0e6719dcfff6e127b40bbdd844accea7e1c";
    const expected_kc_hex = "2baf00efd298de13055c9a6c39e05aee571583384357635e144fa21444239968";

    var root_key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var aad: [5]u8 = undefined;
    var plaintext: [4]u8 = undefined;
    var expected_ciphertext: [4]u8 = undefined;
    var expected_tag: [16]u8 = undefined;
    var expected_dk: [32]u8 = undefined;
    var expected_kc: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&root_key, root_key_hex);
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&aad, aad_hex);
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);
    _ = try std.fmt.hexToBytes(&expected_ciphertext, expected_ciphertext_hex);
    _ = try std.fmt.hexToBytes(&expected_tag, expected_tag_hex);
    _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);
    _ = try std.fmt.hexToBytes(&expected_kc, expected_kc_hex);

    // Test derive function
    const derive_result = DndkGcm.derive(root_key, &nonce, .with_key_commitment);
    try testing.expectEqualSlices(u8, &expected_dk, &derive_result.derived_key);
    try testing.expectEqualSlices(u8, &expected_kc, &derive_result.key_commit.?);

    // Test encryption
    var ciphertext: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    const key_commit = DndkGcm.encrypt(root_key, &nonce, &plaintext, &aad, &ciphertext, &tag, .with_key_commitment);

    try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    try testing.expectEqualSlices(u8, &expected_kc, &key_commit.?);

    // Test decryption
    var decrypted: [4]u8 = undefined;
    try DndkGcm.decrypt(root_key, &nonce, &ciphertext, &aad, tag, &decrypted, .with_key_commitment, key_commit);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "DNDK-GCM test vector A.2 (LN=24, no key commitment)" {
    const root_key_hex = "0100000000000000000000000000000000000000000000000000000000000000";
    const nonce_hex = "000102030405060708090a0b0c0d0e0f1011121314151617";
    const aad_hex = "0100000011";
    const plaintext_hex = "11000001";
    const expected_ciphertext_hex = "7f6e39cc";
    const expected_tag_hex = "b61df0a502c167164e99fa23b7d12b9d";
    const expected_dk_hex = "d974a46fbbeb3dec953ce088ef6b608573248947acf51606de5a1e5b72629197";

    var root_key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var aad: [5]u8 = undefined;
    var plaintext: [4]u8 = undefined;
    var expected_ciphertext: [4]u8 = undefined;
    var expected_tag: [16]u8 = undefined;
    var expected_dk: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&root_key, root_key_hex);
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&aad, aad_hex);
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);
    _ = try std.fmt.hexToBytes(&expected_ciphertext, expected_ciphertext_hex);
    _ = try std.fmt.hexToBytes(&expected_tag, expected_tag_hex);
    _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);

    // Test derive function
    const derive_result = DndkGcm.derive(root_key, &nonce, .no_key_commitment);
    try testing.expectEqualSlices(u8, &expected_dk, &derive_result.derived_key);
    try testing.expect(derive_result.key_commit == null);

    // Test encryption
    var ciphertext: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    const key_commit = DndkGcm.encrypt(root_key, &nonce, &plaintext, &aad, &ciphertext, &tag, .no_key_commitment);

    try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    try testing.expect(key_commit == null);

    // Test decryption
    var decrypted: [4]u8 = undefined;
    try DndkGcm.decrypt(root_key, &nonce, &ciphertext, &aad, tag, &decrypted, .no_key_commitment, null);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "DNDK-GCM test vector A.3 (LN=12, with key commitment)" {
    const root_key_hex = "0100000000000000000000000000000000000000000000000000000000000000";
    const nonce_hex = "000102030405060708090a0b";
    const aad_hex = "0100000011";
    const plaintext_hex = "11000001";
    const expected_ciphertext_hex = "1915d0bd";
    const expected_tag_hex = "187b392eeb9b231a57a852db20e02201";
    const expected_dk_hex = "dfde3c721be6e0b0369770788941a29396c4e50dd81725d3832221fa47d564e1";
    const expected_kc_hex = "675fb3ec6d0e56002333c2504d1b70db47c3713775999c9600bedcfda76f8d8c";

    var root_key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    var aad: [5]u8 = undefined;
    var plaintext: [4]u8 = undefined;
    var expected_ciphertext: [4]u8 = undefined;
    var expected_tag: [16]u8 = undefined;
    var expected_dk: [32]u8 = undefined;
    var expected_kc: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&root_key, root_key_hex);
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&aad, aad_hex);
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);
    _ = try std.fmt.hexToBytes(&expected_ciphertext, expected_ciphertext_hex);
    _ = try std.fmt.hexToBytes(&expected_tag, expected_tag_hex);
    _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);
    _ = try std.fmt.hexToBytes(&expected_kc, expected_kc_hex);

    // Test derive function
    const derive_result = DndkGcm.derive(root_key, &nonce, .with_key_commitment);
    try testing.expectEqualSlices(u8, &expected_dk, &derive_result.derived_key);
    try testing.expectEqualSlices(u8, &expected_kc, &derive_result.key_commit.?);

    // Test encryption
    var ciphertext: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    const key_commit = DndkGcm.encrypt(root_key, &nonce, &plaintext, &aad, &ciphertext, &tag, .with_key_commitment);

    try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    try testing.expectEqualSlices(u8, &expected_kc, &key_commit.?);

    // Test decryption
    var decrypted: [4]u8 = undefined;
    try DndkGcm.decrypt(root_key, &nonce, &ciphertext, &aad, tag, &decrypted, .with_key_commitment, key_commit);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "DNDK-GCM derived key verification for all test vectors" {
    // This test verifies that our Derive function produces the exact derived keys
    // specified in the IETF draft for all test vectors

    const root_key_hex = "0100000000000000000000000000000000000000000000000000000000000000";
    var root_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&root_key, root_key_hex);

    // Test vector A.1: LN=24, with key commitment
    {
        const nonce_hex = "000102030405060708090a0b0c0d0e0f1011121314151617";
        const expected_dk_hex = "3d1480ee39a968d581d16a578bdaf0e6719dcfff6e127b40bbdd844accea7e1c";
        const expected_kc_hex = "2baf00efd298de13055c9a6c39e05aee571583384357635e144fa21444239968";

        var nonce: [24]u8 = undefined;
        var expected_dk: [32]u8 = undefined;
        var expected_kc: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
        _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);
        _ = try std.fmt.hexToBytes(&expected_kc, expected_kc_hex);

        const result = DndkGcm.derive(root_key, &nonce, .with_key_commitment);
        try testing.expectEqualSlices(u8, &expected_dk, &result.derived_key);
        try testing.expectEqualSlices(u8, &expected_kc, &result.key_commit.?);
    }

    // Test vector A.2: LN=24, no key commitment
    {
        const nonce_hex = "000102030405060708090a0b0c0d0e0f1011121314151617";
        const expected_dk_hex = "d974a46fbbeb3dec953ce088ef6b608573248947acf51606de5a1e5b72629197";

        var nonce: [24]u8 = undefined;
        var expected_dk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
        _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);

        const result = DndkGcm.derive(root_key, &nonce, .no_key_commitment);
        try testing.expectEqualSlices(u8, &expected_dk, &result.derived_key);
        try testing.expect(result.key_commit == null);
    }

    // Test vector A.3: LN=12, with key commitment
    {
        const nonce_hex = "000102030405060708090a0b";
        const expected_dk_hex = "dfde3c721be6e0b0369770788941a29396c4e50dd81725d3832221fa47d564e1";
        const expected_kc_hex = "675fb3ec6d0e56002333c2504d1b70db47c3713775999c9600bedcfda76f8d8c";

        var nonce: [12]u8 = undefined;
        var expected_dk: [32]u8 = undefined;
        var expected_kc: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
        _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);
        _ = try std.fmt.hexToBytes(&expected_kc, expected_kc_hex);

        const result = DndkGcm.derive(root_key, &nonce, .with_key_commitment);
        try testing.expectEqualSlices(u8, &expected_dk, &result.derived_key);
        try testing.expectEqualSlices(u8, &expected_kc, &result.key_commit.?);
    }

    // Test vector A.4: LN=12, no key commitment
    {
        const nonce_hex = "000102030405060708090a0b";
        const expected_dk_hex = "13c31bcaf1f11785e1dcb29d5d65541a4b371b1142bb60f39cea823f189e0a17";

        var nonce: [12]u8 = undefined;
        var expected_dk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
        _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);

        const result = DndkGcm.derive(root_key, &nonce, .no_key_commitment);
        try testing.expectEqualSlices(u8, &expected_dk, &result.derived_key);
        try testing.expect(result.key_commit == null);
    }
}

test "DNDK-GCM test vector A.4 (LN=12, no key commitment)" {
    const root_key_hex = "0100000000000000000000000000000000000000000000000000000000000000";
    const nonce_hex = "000102030405060708090a0b";
    const aad_hex = "0100000011";
    const plaintext_hex = "11000001";
    const expected_ciphertext_hex = "b95cf258";
    const expected_tag_hex = "39e74511d997eaafd0f567d13758305b";
    const expected_dk_hex = "13c31bcaf1f11785e1dcb29d5d65541a4b371b1142bb60f39cea823f189e0a17";

    var root_key: [32]u8 = undefined;
    var nonce: [12]u8 = undefined;
    var aad: [5]u8 = undefined;
    var plaintext: [4]u8 = undefined;
    var expected_ciphertext: [4]u8 = undefined;
    var expected_tag: [16]u8 = undefined;
    var expected_dk: [32]u8 = undefined;

    _ = try std.fmt.hexToBytes(&root_key, root_key_hex);
    _ = try std.fmt.hexToBytes(&nonce, nonce_hex);
    _ = try std.fmt.hexToBytes(&aad, aad_hex);
    _ = try std.fmt.hexToBytes(&plaintext, plaintext_hex);
    _ = try std.fmt.hexToBytes(&expected_ciphertext, expected_ciphertext_hex);
    _ = try std.fmt.hexToBytes(&expected_tag, expected_tag_hex);
    _ = try std.fmt.hexToBytes(&expected_dk, expected_dk_hex);

    // Test derive function
    const derive_result = DndkGcm.derive(root_key, &nonce, .no_key_commitment);
    try testing.expectEqualSlices(u8, &expected_dk, &derive_result.derived_key);
    try testing.expect(derive_result.key_commit == null);

    // Test encryption
    var ciphertext: [4]u8 = undefined;
    var tag: [16]u8 = undefined;
    const key_commit = DndkGcm.encrypt(root_key, &nonce, &plaintext, &aad, &ciphertext, &tag, .no_key_commitment);

    try testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try testing.expectEqualSlices(u8, &expected_tag, &tag);
    try testing.expect(key_commit == null);

    // Test decryption
    var decrypted: [4]u8 = undefined;
    try DndkGcm.decrypt(root_key, &nonce, &ciphertext, &aad, tag, &decrypted, .no_key_commitment, null);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
