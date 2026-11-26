// APNs delivery, shared by both relay editions (Node and Cloudflare).
//
// The desktop never talks to Apple: it sends the relay a `push` frame
//
//   {t:'push', id, notifications:[{token, environment, collapseId?, pushType?, priority?, payload}]}
//
// and the relay, which holds the team's APNs signing key, forwards each
// notification to Apple and answers
//
//   {t:'pushed', id, results:[{token, status, reason?}]}      // one per notification
//   {t:'pushed', id, unsupported:true}                         // relay has no APNs key
//
// Everything here runs on WebCrypto + fetch, so it works unchanged inside a
// Worker. The Node edition swaps in `sendWithHttp2` because Node's fetch
// speaks HTTP/1.1 only and APNs requires HTTP/2.

// Apple accepts a provider token for 60 min and answers
// TooManyProviderTokenUpdates when a key's token changes more often than
// every 20 min. One token is minted per key and reused until this age; a
// relay with many tunnels must share it (cloudflare/worker.mjs), not mint
// one per tunnel or per wake-up.
export const TOKEN_TTL_MS = 45 * 60 * 1000;
const HOSTS = { production: 'api.push.apple.com', development: 'api.sandbox.push.apple.com' };
const MAX_BATCH = 64;

const b64url = bytes =>
    btoa(String.fromCharCode(...new Uint8Array(bytes)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
const b64urlText = text => b64url(new TextEncoder().encode(text));

function pemToPkcs8(pem) {
    const body = String(pem)
        .replace(/\\n/g, '\n')
        .replace(/-----[A-Z ]+-----/g, '')
        .replace(/\s+/g, '');
    const raw = atob(body);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
}

/**
 * Mints and caches the ES256 provider token Apple wants in `authorization`.
 * Concurrent callers share one in-flight signature, and a token is replaced
 * only when it is older than TOKEN_TTL_MS or Apple rejected that very token
 * as expired (refresh).
 */
export class ApnsSigner {
    constructor({ key, keyId, teamId, now = Date.now }) {
        if (!key || !keyId || !teamId) throw new Error('APNs signer needs key, keyId and teamId');
        this.pem = key;
        this.keyId = keyId;
        this.teamId = teamId;
        this.now = now;
        this.cryptoKey = null;
        this.cached = null; // {token, at}
        this.inflight = null;
    }

    /** The cached {token, at} while it is fresh, else a newly minted one. */
    async current() {
        if (this.cached && this.now() - this.cached.at < TOKEN_TTL_MS) return this.cached;
        return this.mintOnce();
    }

    async token() {
        return (await this.current()).token;
    }

    /** Apple answered ExpiredProviderToken for `rejected`: mint anew, unless a newer token already replaced it. */
    async refresh(rejected) {
        if (this.cached && this.cached.token === rejected) this.cached = null;
        return (await this.current()).token;
    }

    mintOnce() {
        if (!this.inflight)
            this.inflight = this.mint().finally(() => {
                this.inflight = null;
            });
        return this.inflight;
    }

    async mint() {
        const now = this.now();
        if (!this.cryptoKey) {
            this.cryptoKey = await crypto.subtle.importKey('pkcs8', pemToPkcs8(this.pem), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
        }
        const header = b64urlText(JSON.stringify({ alg: 'ES256', kid: this.keyId }));
        const claims = b64urlText(JSON.stringify({ iss: this.teamId, iat: Math.floor(now / 1000) }));
        const signingInput = `${header}.${claims}`;
        // WebCrypto ECDSA signatures are already r||s (IEEE P1363), which is
        // exactly the JWS encoding — no DER juggling.
        const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.cryptoKey, new TextEncoder().encode(signingInput));
        this.cached = { token: `${signingInput}.${b64url(sig)}`, at: now };
        return this.cached;
    }
}

/**
 * A provider token kept somewhere else (the Cloudflare edition's one token
 * Durable Object), cached here with the age it was minted at. `fetch(rejected)`
 * returns {token, at}; `rejected` is the token Apple called expired, or null.
 * Same interface as ApnsSigner (token, refresh), one in-flight fetch at a time.
 */
export class SharedApnsToken {
    constructor(fetch, { now = Date.now } = {}) {
        this.fetch = fetch;
        this.now = now;
        this.cached = null;
        this.inflight = null;
    }

    async token() {
        if (this.cached && this.now() - this.cached.at < TOKEN_TTL_MS) return this.cached.token;
        return (await this.load(null)).token;
    }

    async refresh(rejected) {
        if (this.inflight) await this.inflight.catch(() => {});
        if (this.cached && this.cached.token !== rejected && this.now() - this.cached.at < TOKEN_TTL_MS) return this.cached.token;
        return (await this.load(rejected)).token;
    }

    load(rejected) {
        if (!this.inflight)
            this.inflight = (async () => {
                const got = await this.fetch(rejected);
                if (!got || typeof got.token !== 'string' || typeof got.at !== 'number') throw new Error('APNs token source returned no token');
                this.cached = { token: got.token, at: got.at };
                return this.cached;
            })().finally(() => {
                this.inflight = null;
            });
        return this.inflight;
    }
}

/** Whether Apple's answer asks for a fresh provider token (retry the notification once). */
export function isExpiredProviderToken(result) {
    return result?.status === 403 && result.reason === 'ExpiredProviderToken';
}

/** Build a signer from an env-like object, or null when no key is configured. */
export function apnsSignerFromEnv(env) {
    const key = env.APNS_KEY;
    if (!key) return null;
    return new ApnsSigner({ key, keyId: env.APNS_KEY_ID, teamId: env.APNS_TEAM_ID });
}

export function apnsHost(environment) {
    return HOSTS[environment === 'development' ? 'development' : 'production'];
}

export function apnsTopic(env) {
    return env.APNS_TOPIC || 'me.yetone.alma';
}

/** Sanity-check one notification from the agent; returns a reason or null. */
export function validateNotification(n) {
    if (!n || typeof n !== 'object') return 'BadNotification';
    if (typeof n.token !== 'string' || !/^[0-9a-f]{64,200}$/.test(n.token)) return 'BadDeviceToken';
    if (!n.payload || typeof n.payload !== 'object') return 'PayloadEmpty';
    if (JSON.stringify(n.payload).length > 4096) return 'PayloadTooLarge';
    return null;
}

export function apnsRequestHeaders(token, topic, n) {
    const headers = {
        authorization: `bearer ${token}`,
        // A Live Activity update goes to the app's `.push-type.liveactivity` topic.
        'apns-topic': n.pushType === 'liveactivity' ? `${topic}.push-type.liveactivity` : topic,
        'apns-push-type': n.pushType === 'liveactivity' ? 'liveactivity' : 'alert',
        'apns-priority': n.priority === 5 ? '5' : '10',
        'content-type': 'application/json',
    };
    if (typeof n.collapseId === 'string' && n.collapseId) headers['apns-collapse-id'] = n.collapseId.slice(0, 64);
    return headers;
}

export function clampBatch(notifications) {
    return Array.isArray(notifications) ? notifications.slice(0, MAX_BATCH) : [];
}

/** Read APNs' answer into {status, reason}. Apple's body is `{"reason":"..."}`. */
export function resultFromResponse(status, bodyText) {
    if (status === 200) return { status };
    let reason;
    try {
        reason = JSON.parse(bodyText || '{}').reason;
    } catch {
        /* not JSON */
    }
    return { status, reason: typeof reason === 'string' ? reason : undefined };
}

/**
 * Deliver a batch through the platform `fetch` (Cloudflare Workers negotiate
 * HTTP/2 to Apple by themselves). Never throws: a network failure becomes
 * `{status: 0, reason}` for that token.
 */
export async function sendWithFetch(signer, topic, notifications, fetchImpl = fetch) {
    const results = [];
    for (const n of clampBatch(notifications)) {
        const invalid = validateNotification(n);
        if (invalid) {
            results.push({ token: typeof n?.token === 'string' ? n.token : '', status: 400, reason: invalid });
            continue;
        }
        try {
            const post = async auth => {
                const res = await fetchImpl(`https://${apnsHost(n.environment)}/3/device/${n.token}`, {
                    method: 'POST',
                    headers: apnsRequestHeaders(auth, topic, n),
                    body: JSON.stringify(n.payload),
                });
                return resultFromResponse(res.status, await res.text());
            };
            const auth = await signer.token();
            let result = await post(auth);
            if (isExpiredProviderToken(result)) result = await post(await signer.refresh(auth));
            results.push({ token: n.token, ...result });
        } catch (err) {
            results.push({ token: n.token, status: 0, reason: err instanceof Error ? err.message : String(err) });
        }
    }
    return results;
}
