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
            var msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
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
            var msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
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

    var msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    var msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    var c2 = c2_buf[0..msg_len];

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

    var msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    var msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    var c2 = c2_buf[0..msg_len];

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

    var msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
    msg_len = 32;

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    var msg = msg_buf[0..msg_len];
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
    const c2 = c[2 * c.len / 3 ..];

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

    var msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    var msg = msg_buf[0..msg_len];
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

    const c0 = c[0 .. c.len / 3];
    const c1 = c[c.len / 3 .. 2 * c.len / 3];
    const c2 = c[2 * c.len / 3 ..];

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
    var ret = aegis.aegis128x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "9958ad79ff1feea50a27d5dd88728d157a4ce0cd996b9fffb4fde113ef646de4aa67278fb1ebcb6571526b309d708447c818ffc3d84c9c73b0cca3040bb85b81d366311956f4cb1a66b02b25b58a7f759797169b0e398c4db16c9a577d4de1805d646b823fa095ec34feefb58768efc06d9516c55b653f91";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "179247ab85ea2c4f9f712cac8bb7c9d3";
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
            var msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x2_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
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
            var msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x4_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
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
    var ret = aegis.aegis128x4_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "9958ad79ff1feea50a27d5dd88728d157a4ce0cd996b9fffb4fde113ef646de46e4c5230174a6268f89f01d557879360a9068d7cb825bb0e8a97ea2e82059f69aa67278fb1ebcb6571526b309d708447c818ffc3d84c9c73b0cca3040bb85b8193fc9a4499e384ae87bfeaa46f514b6330c147c3ddbb6e94";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "58038e00f6b7e861e2badb160beb71d4";
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
    const msg = [_]u8{ 5, 6, 7, 8 } ** 3;
    var c = [_]u8{0} ** msg.len;
    var mac = [_]u8{0} ** 16;
    var ret = aegis.aegis256x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "a0b3f5b6b93db779c9d1b9de";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "fd2e93a6eb0b74dc30eb984fbec1d657";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2 = [_]u8{0} ** msg.len;
    ret = aegis.aegis256x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Unauthenticated encryption" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;

    random.bytes(&msg);
    aegis.aegis128l_encrypt_unauthenticated(&msg2, &msg, msg.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
    aegis.aegis128l_decrypt_unauthenticated(&msg2, &msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Random stream" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;
    aegis.aegis128l_randombytes_deterministic(&msg, msg.len, &nonce, &key);
    aegis.aegis128l_randombytes_deterministic(&msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
    nonce[0] ^= 0x01;
    aegis.aegis128l_randombytes_deterministic(&msg2, msg2.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
}
