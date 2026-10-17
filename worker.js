// ═══════════════════════════════════════════════════════
// Real Bagrid — servidor (Cloudflare Worker)
// ═══════════════════════════════════════════════════════
// Serve o site normalmente e cuida de um único endereço extra:
//   POST /api/notify  → envia uma notificação para todos os celulares inscritos.
// Só o admin consegue usar: o pedido precisa vir com o login do Firebase,
// e é o próprio Firebase que confere esse login ao ler a lista de inscritos.
//
// Configuração necessária no Cloudflare (Settings → Variables and Secrets):
//   VAPID_PRIVATE  (tipo Secret) → chave privada das notificações

const DB_URL = 'https://realbagrid-1134e-default-rtdb.firebaseio.com';
const VAPID_PUBLIC = 'BEUa95vXGNcxX3QOIn53nC_Zb7g7J8PAD7pPTdqZtJms0RKUffsKP-QVRRqpsoE7D7_8sq2deXoximwnqTbhw7s';
const VAPID_SUBJECT = 'https://www.realbagrid.com.br';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/notify') {
      if (request.method !== 'POST') return json({ erro: 'Use POST' }, 405);
      try {
        return await notify(request, env);
      } catch (err) {
        return json({ erro: String(err && err.message || err) }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
  });
}

async function notify(request, env) {
  if (!env.VAPID_PRIVATE) return json({ erro: 'VAPID_PRIVATE não configurada no Cloudflare' }, 500);

  const token = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) return json({ erro: 'Sem login' }, 401);

  const body = await request.json().catch(() => ({}));
  const titulo = String(body.titulo || '').slice(0, 120);
  const texto = String(body.texto || '').slice(0, 300);
  const link = String(body.url || '/').startsWith('/') ? String(body.url || '/') : '/';
  const jids = Array.isArray(body.jids) ? body.jids.map(String) : null;   // opcional: só para estes jogadores
  if (!titulo) return json({ erro: 'Falta o título' }, 400);

  // Lê os inscritos usando o login do admin (o Firebase recusa se o login for inválido)
  const r = await fetch(`${DB_URL}/push/subs.json?auth=${encodeURIComponent(token)}`);
  if (r.status === 401 || r.status === 403) return json({ erro: 'Login inválido ou expirado' }, 401);
  if (!r.ok) return json({ erro: `Firebase respondeu ${r.status}` }, 502);
  const subs = (await r.json()) || {};

  const payload = new TextEncoder().encode(JSON.stringify({ titulo, texto, url: link }));
  let enviadas = 0, falhas = 0, removidas = 0;

  await Promise.all(Object.entries(subs).map(async ([key, sub]) => {
    if (!sub || !sub.endpoint || !sub.keys) return;
    if (jids && !jids.includes(sub.jid || '')) return;
    try {
      const res = await sendPush(sub, payload, env.VAPID_PRIVATE);
      if (res.status === 404 || res.status === 410) {
        // celular desinstalou o app ou desativou as notificações → limpa
        await fetch(`${DB_URL}/push/subs/${key}.json?auth=${encodeURIComponent(token)}`, { method: 'DELETE' });
        removidas++;
      } else if (res.ok) {
        enviadas++;
      } else {
        falhas++;
      }
    } catch (e) {
      falhas++;
    }
  }));

  return json({ enviadas, falhas, removidas });
}

// ─── Web Push (RFC 8291 / RFC 8292) ──────────────────────
const enc = new TextEncoder();

function b64uDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64uEncode(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function concat(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
async function hkdf(salt, ikm, info, bytes) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, bytes * 8);
  return new Uint8Array(bits);
}

async function vapidHeader(endpoint, privateD) {
  const pub = b64uDecode(VAPID_PUBLIC);
  const jwk = {
    kty: 'EC', crv: 'P-256', d: privateD,
    x: b64uEncode(pub.slice(1, 33)), y: b64uEncode(pub.slice(33, 65)), ext: true
  };
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const header = b64uEncode(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64uEncode(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: VAPID_SUBJECT
  })));
  const unsigned = `${header}.${claims}`;
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(unsigned));
  return `vapid t=${unsigned}.${b64uEncode(sig)}, k=${VAPID_PUBLIC}`;
}

export async function encryptPayload(sub, payload) {
  const uaPublic = b64uDecode(sub.keys.p256dh);
  const authSecret = b64uDecode(sub.keys.auth);

  const local = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));

  const ikm = await hkdf(authSecret, shared, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const plain = concat(payload, new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, plain));

  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

export async function sendPush(sub, payload, privateD) {
  const body = await encryptPayload(sub, payload);
  return fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': await vapidHeader(sub.endpoint, privateD),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
      'Urgency': 'high'
    },
    body
  });
}
