// node --test test
import assert from 'node:assert/strict';
import test from 'node:test';

import { ApnsSigner, SharedApnsToken, TOKEN_TTL_MS, apnsRequestHeaders, sendWithFetch } from '../apns.mjs';

test('an alert goes to the app topic', () => {
    const h = apnsRequestHeaders('jwt', 'me.yetone.alma', { collapseId: 'x' });
    assert.equal(h['apns-topic'], 'me.yetone.alma');
    assert.equal(h['apns-push-type'], 'alert');
    assert.equal(h['apns-priority'], '10');
    assert.equal(h['apns-collapse-id'], 'x');
});

test('a Live Activity update goes to its own topic', () => {
    const h = apnsRequestHeaders('jwt', 'me.yetone.alma', { pushType: 'liveactivity', priority: 5 });
    assert.equal(h['apns-topic'], 'me.yetone.alma.push-type.liveactivity');
    assert.equal(h['apns-push-type'], 'liveactivity');
    assert.equal(h['apns-priority'], '5');
});

// ── provider token reuse (TooManyProviderTokenUpdates) ──


async function testKeyPem() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const der = Buffer.from(await crypto.subtle.exportKey('pkcs8', pair.privateKey)).toString('base64');
    return `-----BEGIN PRIVATE KEY-----\n${der}\n-----END PRIVATE KEY-----`;
}

function clock(start = 1_800_000_000_000) {
    const c = { t: start, now: () => c.t };
    return c;
}

test('one provider token is signed for concurrent sends and reused until it ages out', async () => {
    const c = clock();
    const signer = new ApnsSigner({ key: await testKeyPem(), keyId: 'KEY', teamId: 'TEAM', now: c.now });
    let signs = 0;
    const mint = signer.mint.bind(signer);
    signer.mint = () => (signs++, mint());
    const burst = await Promise.all([signer.token(), signer.token(), signer.token()]);
    assert.equal(signs, 1);
    assert.equal(new Set(burst).size, 1);
    c.t += 20 * 60 * 1000;
    assert.equal(await signer.token(), burst[0]);
    c.t += TOKEN_TTL_MS;
    const next = await signer.token();
    assert.equal(signs, 2);
    assert.notEqual(next, burst[0]);
    const claims = JSON.parse(Buffer.from(next.split('.')[1], 'base64url').toString());
    assert.deepEqual(claims, { iss: 'TEAM', iat: Math.floor(c.t / 1000) });
});

test('an expired token is replaced once, and a stale rejection keeps the newer token', async () => {
    const signer = new ApnsSigner({ key: await testKeyPem(), keyId: 'KEY', teamId: 'TEAM' });
    const first = await signer.token();
    const [a, b] = await Promise.all([signer.refresh(first), signer.refresh(first)]);
    assert.notEqual(a, first);
    assert.equal(a, b);
    assert.equal(await signer.refresh(first), a);
});

test('a shared token source is asked once per burst and only again when the token ages out', async () => {
    const c = clock();
    const asks = [];
    const source = new SharedApnsToken(
        async rejected => {
            asks.push(rejected);
            return { token: `t${asks.length}`, at: c.t };
        },
        { now: c.now }
    );
    assert.deepEqual(await Promise.all([source.token(), source.token(), source.token()]), ['t1', 't1', 't1']);
    c.t += TOKEN_TTL_MS - 1;
    assert.equal(await source.token(), 't1');
    assert.equal(await source.refresh('t0'), 't1');
    assert.equal(await source.refresh('t1'), 't2');
    assert.deepEqual(asks, [null, 't1']);
    c.t += TOKEN_TTL_MS;
    assert.equal(await source.token(), 't3');
});

test('a batch reuses one token, and ExpiredProviderToken is retried once with a fresh one', async () => {
    const signer = new ApnsSigner({ key: await testKeyPem(), keyId: 'KEY', teamId: 'TEAM' });
    const first = await signer.token();
    const seen = [];
    const fetchImpl = async (url, init) => {
        const auth = init.headers.authorization;
        seen.push(auth);
        if (auth === `bearer ${first}`) return new Response(JSON.stringify({ reason: 'ExpiredProviderToken' }), { status: 403 });
        return new Response('', { status: 200 });
    };
    const token = c => c.repeat(64);
    const results = await sendWithFetch(
        signer,
        'me.yetone.alma',
        ['a', 'b', 'c'].map(c => ({ token: token(c), payload: { aps: {} } })),
        fetchImpl
    );
    assert.deepEqual(
        results.map(r => r.status),
        [200, 200, 200]
    );
    // a: expired, retried with a fresh token; b and c use that one.
    assert.equal(seen.length, 4);
    assert.equal(seen[0], `bearer ${first}`);
    assert.equal(new Set(seen.slice(1)).size, 1);
    assert.notEqual(seen[1], seen[0]);
});

test('an expired token that stays rejected is not retried twice', async () => {
    const signer = new ApnsSigner({ key: await testKeyPem(), keyId: 'KEY', teamId: 'TEAM' });
    let calls = 0;
    const results = await sendWithFetch(
        signer,
        'me.yetone.alma',
        [{ token: 'a'.repeat(64), payload: { aps: {} } }],
        async () => (calls++, new Response(JSON.stringify({ reason: 'ExpiredProviderToken' }), { status: 403 }))
    );
    assert.equal(calls, 2);
    assert.deepEqual(results, [{ token: 'a'.repeat(64), status: 403, reason: 'ExpiredProviderToken' }]);
});
