const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const random = std.crypto.random;
const testing = std.testing;

const max_msg_len: usize = 1000;
const max_ad_len: usize = 1000;
const iterations = 50000;

test "aegis-128l - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-256 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis256_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128l - incremental encryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var c2_buf: [c_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    _ = &c;
    var c2 = c2_buf[0..msg_len];
    _ = &c2;

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis128l_state = undefined;
    var written: usize = undefined;

    aegis.aegis128l_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    var cx = c;

    const m0 = msg[0 .. msg.len / 3];
    const m1 = msg[msg.len / 3 .. 2 * msg.len / 3];
    const m2 = msg[2 * msg.len / 3 ..];

    var ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, cx.len, &written, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, cx.len, &written, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, cx.len, &written, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis128l_state_encrypt_detached_final(&st, cx.ptr, cx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis128l_encrypt_detached(c2.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, c, c2);

    var msg2 = msg2_buf[0..msg_len];
    _ = &msg2;
    ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, msg, msg2);
}

test "aegis-256 - incremental encryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var c2_buf: [c_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    _ = &c;
    var c2 = c2_buf[0..msg_len];
    _ = &c2;

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis256_state = undefined;
    var written: usize = undefined;

    aegis.aegis256_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    var cx = c;

    const m0 = msg[0 .. msg.len / 3];
    const m1 = msg[msg.len / 3 .. 2 * msg.len / 3];
    const m2 = msg[2 * msg.len / 3 ..];

    var ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_detached_final(&st, cx.ptr, cx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis256_encrypt_detached(c2.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, c, c2);

    var msg2 = msg2_buf[0..msg_len];
    _ = &msg2;
    ret = aegis.aegis256_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, msg, msg2);
}

test "aegis-256 - incremental encryption 2" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg: [633]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var ad: [10]u8 = undefined;
    var c: [msg.len + mac_len]u8 = undefined;
    var c2: [c.len]u8 = undefined;

    random.bytes(&ad);
    random.bytes(&msg);

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis256_state = undefined;
    var written: usize = undefined;

    aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);

    var cx: []u8 = c[0..];

    const m0 = msg[0..11];
    const m1 = msg[11 .. 11 + 21];
    const m2 = msg[11 + 21 .. 11 + 21 + 311];
    const m3 = msg[11 + 21 + 311 ..];

    var ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, cx.len, &written, m3.ptr, m3.len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];

    ret = aegis.aegis256_state_encrypt_final(&st, cx.ptr, cx.len, &written, mac_len);
    try testing.expectEqual(ret, 0);
    cx = cx[written..];
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis256_encrypt(&c2, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, &c, &c2);

    ret = aegis.aegis256_decrypt(&msg2, &c, c.len, mac_len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-128l - incremental decryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis128l_state = undefined;
    var written: usize = undefined;

    const c0 = c[0 .. c.len / 3];
    const c1 = c[c.len / 3 .. 2 * c.len / 3];
    var c2 = c[2 * c.len / 3 ..];
    _ = &c2;

    var mx = msg2_buf[0..c.len];

    aegis.aegis128l_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    ret = aegis.aegis128l_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c0.ptr, c0.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis128l_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c1.ptr, c1.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis128l_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c2.ptr, c2.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis128l_state_decrypt_detached_final(&st, mx.ptr, mx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    try testing.expectEqual(mx.len, 0);
    try testing.expectEqualSlices(u8, msg, msg2_buf[0..msg.len]);
}

test "aegis-256 - incremental decryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis256_state = undefined;
    var written: usize = undefined;

    var c0 = c[0 .. c.len / 3];
    _ = &c0;
    var c1 = c[c.len / 3 .. 2 * c.len / 3];
    _ = &c1;
    var c2 = c[2 * c.len / 3 ..];
    _ = &c2;

    var mx = msg2_buf[0..c.len];

    aegis.aegis256_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    ret = aegis.aegis256_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c0.ptr, c0.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis256_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c1.ptr, c1.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis256_state_decrypt_detached_update(&st, mx.ptr, mx.len, &written, c2.ptr, c2.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    ret = aegis.aegis256_state_decrypt_detached_final(&st, mx.ptr, mx.len, &written, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    mx = mx[written..];

    try testing.expectEqual(mx.len, 0);
    try testing.expectEqualSlices(u8, msg, msg2_buf[0..msg.len]);
}

test "aegis-128x2 - test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 4, 5, 6, 7 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis128x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "5795544301997f93621b278809d6331b3bfa6f18e90db12c4aa35965b5e98c5fc6fb4e54bcb6111842c20637252eff747cb3a8f85b37de80919a589fe0f24872bc926360696739e05520647e390989e1eb5fd42f99678a0276a498f8c454761c9d6aacb647ad56be62b29c22cd4b5761b38f43d5a5ee062f";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "1aebc200804f405cab637f2adebb6d77";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis128x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-128x2 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x2_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128x2_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128x4 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            const c = c_buf[0..msg_len];

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x4_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128x4_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128x4 - test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 4, 5, 6, 7 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis128x4_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "e836118562f4479c9d35c17356a833114c21f9aa39e4dda5e5c87f4152a00fce9a7c38f832eafe8b1c12f8a7cf12a81a1ad8a9c24ba9dedfbdaa586ffea67ddc801ea97d9ab4a872f42d0e352e2713dacd609f9442c17517c5a29daf3e2a3fac4ff6b1380c4e46df7b086af6ce6bc1ed594b8dd64aed2a7e";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "0e56ab94e2e85db80f9d54010caabfb4";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis128x4_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-256x2 - test vector" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 5, 6, 7, 8 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis256x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x2_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "73110d21a920608fd77b580f1e4428087a7365cb153b4eeca6b62e1a70f7f9a8d1f31f17da4c3acfacb2517f2f5e15758c35532e33751a964d18d29a599d2dc07f9378339b9d8c9fa03d30a4d7837cc8eb8b99bcbba2d11cd1a0f994af2b8f947ef18473bd519e5283736758480abc990e79d4ccab93dde9";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "94a3bd44ad3381e36335014620ee638e";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis256x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-256x4 - test vector" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = [_]u8{ 1, 2, 3, 4 } ** 2;
    const msg = [_]u8{ 5, 6, 7, 8 } ** 30;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var mac256 = [_]u8{0} ** 32;
    var ret = aegis.aegis256x4_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x4_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "bec109547f8316d598b3b7d947ad4c0ef5b98e217cffa0d858ad49ae34109a95abc5b5fada820c4d6ae2fca0f5e2444e52a04a1edb7bec71408de3e19950052194506be3ba6a4de51a15a577ea0e4c14f7539a13e751a555f48d0f49fecffb220525e60d381e2efa803b09b7164ba59fdc66656affd51e06";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "ec44b512d713f745547be345bcc66b6c";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis256x4_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Unauthenticated encryption" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [16]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;

    random.bytes(&msg);
    aegis.aegis128l_encrypt_unauthenticated(&msg2, &msg, msg.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
    aegis.aegis128l_decrypt_unauthenticated(&msg2, &msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Random stream" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var nonce = [16]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;
    aegis.aegis128l_stream(&msg, msg.len, &nonce, &key);
    aegis.aegis128l_stream(&msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
    nonce[0] ^= 0x01;
    aegis.aegis128l_stream(&msg2, msg2.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
}

test "aegis128l - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{0} ** 16;
    const msg = [_]u8{ 1, 2, 3 } ** 100;
    const msg2 = [_]u8{ 4, 5, 6, 7, 8 } ** 100 ++ [_]u8{0};
    var st0: aegis.aegis128l_mac_state = undefined;
    aegis.aegis128l_mac_init(&st0, &key, &nonce);

    var st: aegis.aegis128l_mac_state = undefined;
    aegis.aegis128l_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128l_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_mac_state_clone(&st, &st0);
    ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128l_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128l_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis128x2 - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{0} ** 16;
    const msg = [_]u8{ 1, 2, 3 } ** 100;
    const msg2 = [_]u8{ 4, 5, 6, 7, 8 } ** 100 ++ [_]u8{0};
    var st0: aegis.aegis128x2_mac_state = undefined;
    aegis.aegis128x2_mac_init(&st0, &key, &nonce);

    var st: aegis.aegis128x2_mac_state = undefined;
    aegis.aegis128x2_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128x2_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x2_mac_state_clone(&st, &st0);
    ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x2_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128x2_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128x2_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expect(!std.mem.eql(u8, &mac, &mac2));
}

test "aegis128x4 - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{0} ** 16;
    const msg = [_]u8{ 1, 2, 3 } ** 100 ++ [_]u8{0};
    const msg2 = [_]u8{ 4, 5, 6, 7, 8 } ** 100;
    var st0: aegis.aegis128x4_mac_state = undefined;
    aegis.aegis128x4_mac_init(&st0, &key, &nonce);

    var st: aegis.aegis128x4_mac_state = undefined;
    aegis.aegis128x4_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128x4_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x4_mac_state_clone(&st, &st0);
    ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x4_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128x4_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128x4_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expect(!std.mem.eql(u8, &mac, &mac2));
}

test "aegis128l - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ [_]u8{0x00} ** (16 - 2);
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ [_]u8{0x00} ** (16 - 3);
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis128l_mac_state = undefined;
    var ret: c_int = undefined;
    aegis.aegis128l_mac_init(&st, &key, &nonce);
    ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis128l_mac_reset(&st);
    ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "3982e98c66fa9232e9190ec57b120725";
    const expected256_hex = "a7d01b4636e8d312af8b65b3bb680feb8ffd62aa234584001b1e419b4b40c317";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

test "aegis128x2 - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ [_]u8{0x00} ** (16 - 2);
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ [_]u8{0x00} ** (16 - 3);
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis128x2_mac_state = undefined;
    var ret: c_int = undefined;
    aegis.aegis128x2_mac_init(&st, &key, &nonce);
    ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis128x2_mac_reset(&st);
    ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "f472304012396667f51ab7450d87f460";
    const expected256_hex = "f376288f13b51c73ecb814922919a31f2cbe1fd322a0062ef7860327a2bc3159";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

test "aegis128x4 - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ [_]u8{0x00} ** (16 - 2);
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ [_]u8{0x00} ** (16 - 3);
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis128x4_mac_state = undefined;
    var ret: c_int = undefined;
    aegis.aegis128x4_mac_init(&st, &key, &nonce);
    ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis128x4_mac_reset(&st);
    ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "3742a0bf0a9e8604841fe520fc57621c";
    const expected256_hex = "3da44ead4e192d0df3c47c994c242b69dab2fdf0d98f58f96838d634ab945d3a";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

// Wycheproof tests

const JsonTest = struct {
    tcId: u64,
    key: []const u8,
    iv: []const u8,
    aad: []const u8,
    msg: []const u8,
    ct: []const u8,
    tag: []const u8,
    result: []const u8,
};
const JsonTestGroup = struct {
    type: []const u8,
    tests: []const JsonTest,
};
const JsonTests = struct {
    testGroups: []JsonTestGroup,
};
const Result = enum {
    valid,
    invalid,
};

const heap = std.heap;
const zstd = std.compress.zstd;

test "aegis128l - wycheproof" {
    const alloc = std.testing.allocator;
    var fbs = std.io.fixedBufferStream(@embedFile("wycheproof/aegis128L_test.json.zst"));
    var window_buffer: [zstd.DecompressorOptions.default_window_buffer_len]u8 = undefined;
    var decompressor = zstd.decompressor(fbs.reader(), .{ .window_buffer = &window_buffer });
    const json = try decompressor.reader().readAllAlloc(alloc, 1000000);
    defer alloc.free(json);
    const parsed = try std.json.parseFromSlice(JsonTests, alloc, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    for (parsed.value.testGroups) |test_group| {
        if (!std.mem.eql(u8, "AeadTest", test_group.type)) continue;
        for (test_group.tests) |t| {
            var arena = heap.ArenaAllocator.init(alloc);
            defer arena.deinit();
            var arena_alloc = arena.allocator();
            var key: [16]u8 = undefined;
            var nonce: [16]u8 = undefined;
            var tag: [16]u8 = undefined;
            const aad = try arena_alloc.alloc(u8, t.aad.len / 2);
            const ct = try arena_alloc.alloc(u8, t.ct.len / 2);
            const msg = try arena_alloc.alloc(u8, t.msg.len / 2);
            const expected_msg = try arena_alloc.alloc(u8, t.msg.len / 2);
            _ = try std.fmt.hexToBytes(&key, t.key);
            _ = try std.fmt.hexToBytes(&nonce, t.iv);
            _ = try std.fmt.hexToBytes(&tag, t.tag);
            _ = try std.fmt.hexToBytes(aad, t.aad);
            _ = try std.fmt.hexToBytes(expected_msg, t.msg);
            _ = try std.fmt.hexToBytes(ct, t.ct);
            const c_res = aegis.aegis128l_decrypt_detached(msg.ptr, ct.ptr, ct.len, &tag, tag.len, aad.ptr, aad.len, &nonce, &key);
            const res: Result = if (c_res == 0) res: {
                if (std.mem.eql(u8, msg, expected_msg)) break :res .valid;
                break :res .invalid;
            } else .invalid;
            if ((std.mem.eql(u8, "invalid", t.result) and res == .valid) or (std.mem.eql(u8, "valid", t.result) and res == .invalid)) {
                std.debug.print("Test failed: {}\n", .{t.tcId});
                try std.testing.expect(false);
            }
        }
    }
}

test "aegis256 - wycheproof" {
    const alloc = std.testing.allocator;
    var fbs = std.io.fixedBufferStream(@embedFile("wycheproof/aegis256_test.json.zst"));
    var window_buffer: [zstd.DecompressorOptions.default_window_buffer_len]u8 = undefined;
    var decompressor = zstd.decompressor(fbs.reader(), .{ .window_buffer = &window_buffer });
    const json = try decompressor.reader().readAllAlloc(alloc, 1000000);
    defer alloc.free(json);
    const parsed = try std.json.parseFromSlice(JsonTests, alloc, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    for (parsed.value.testGroups) |test_group| {
        if (!std.mem.eql(u8, "AeadTest", test_group.type)) continue;
        for (test_group.tests) |t| {
            var arena = heap.ArenaAllocator.init(alloc);
            defer arena.deinit();
            var arena_alloc = arena.allocator();
            var key: [32]u8 = undefined;
            var nonce: [32]u8 = undefined;
            var tag: [16]u8 = undefined;
            const aad = try arena_alloc.alloc(u8, t.aad.len / 2);
            const ct = try arena_alloc.alloc(u8, t.ct.len / 2);
            const msg = try arena_alloc.alloc(u8, t.msg.len / 2);
            const expected_msg = try arena_alloc.alloc(u8, t.msg.len / 2);
            _ = try std.fmt.hexToBytes(&key, t.key);
            _ = try std.fmt.hexToBytes(&nonce, t.iv);
            _ = try std.fmt.hexToBytes(&tag, t.tag);
            _ = try std.fmt.hexToBytes(aad, t.aad);
            _ = try std.fmt.hexToBytes(expected_msg, t.msg);
            _ = try std.fmt.hexToBytes(ct, t.ct);
            const c_res = aegis.aegis256_decrypt_detached(msg.ptr, ct.ptr, ct.len, &tag, tag.len, aad.ptr, aad.len, &nonce, &key);
            const res: Result = if (c_res == 0) res: {
                if (std.mem.eql(u8, msg, expected_msg)) break :res .valid;
                break :res .invalid;
            } else .invalid;
            if ((std.mem.eql(u8, "invalid", t.result) and res == .valid) or (std.mem.eql(u8, "valid", t.result) and res == .invalid)) {
                std.debug.print("Test failed: {}\n", .{t.tcId});
                try std.testing.expect(false);
            }
        }
    }
}
