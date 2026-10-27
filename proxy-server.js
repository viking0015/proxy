// Simple web proxy. Requires Node 18+. No dependencies.
// Run:  node proxy-server.js   then open http://localhost:8080
// Keep it on localhost or behind a login: an open proxy on the internet gets abused.

const http = require('http');
const dns = require('dns').promises;
const net = require('net');

const PORT = process.env.PORT || 8080;

const HOME = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proxy</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:0 16px}
form{display:flex;gap:8px}input{flex:1;padding:10px;font-size:16px}button{padding:10px 16px;font-size:16px}</style>
<h1>Web proxy</h1>
<form action="/proxy" method="get">
<input name="url" placeholder="https://example.com" required autofocus>
<button>Go</button></form>`;

// Block requests to private/local addresses so the proxy can't reach your own network.
function isPrivate(ip) {
  if (net.isIPv6(ip)) return ip === '::1' || /^(fc|fd|fe80)/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) ||
         (a === 192 && b === 168) || (a === 169 && b === 254);
}

function rewriteHtml(html, base) {
  const abs = (u) => {
    try { return '/proxy?url=' + encodeURIComponent(new URL(u, base).href); }
    catch { return u; }
  };
  return html.replace(
    /\b(href|src|action|poster)=("([^"]*)"|'([^']*)')/gi,
    (m, attr, quoted, dq, sq) => {
      const val = dq ?? sq;
      if (/^(#|data:|javascript:|mailto:|tel:)/i.test(val)) return m;
      return `${attr}="${abs(val)}"`;
    }
  ).replace(/\bsrcset=("[^"]*")/gi, '').replace(/<meta[^>]+http-equiv=["']?refresh[^>]*>/gi, '');
}

http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host}`);

  if (reqUrl.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(HOME);
  }
  if (reqUrl.pathname !== '/proxy') { res.writeHead(404); return res.end('Not found'); }

  let target;
  try {
    let raw = reqUrl.searchParams.get('url') || '';
    if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
    target = new URL(raw);
    if (!['http:', 'https:'].includes(target.protocol)) throw new Error('bad protocol');
    const addrs = await dns.lookup(target.hostname, { all: true });
    if (addrs.some((a) => isPrivate(a.address))) {
      res.writeHead(403); return res.end('Blocked: private address');
    }
  } catch {
    res.writeHead(400); return res.end('Invalid URL');
  }

  try {
    const upstream = await fetch(target.href, {
      redirect: 'follow',
      headers: {
        'user-agent': req.headers['user-agent'] || 'Mozilla/5.0',
        'accept': req.headers['accept'] || '*/*',
        'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      },
    });
    const type = upstream.headers.get('content-type') || 'application/octet-stream';
    const body = Buffer.from(await upstream.arrayBuffer());
    const finalUrl = upstream.url || target.href;

    // Drop security headers that would stop the page from rendering through the proxy.
    const headers = { 'content-type': type };
    if (type.includes('text/html')) {
      const html = rewriteHtml(body.toString('utf8'), finalUrl);
      res.writeHead(upstream.status, headers);
      return res.end(html);
    }
    res.writeHead(upstream.status, headers);
    res.end(body);
  } catch (e) {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('Could not fetch that page: ' + e.message);
  }
}).listen(PORT, '0.0.0.0', () => console.log(`Proxy running at http://localhost:${PORT}`));