// proxy.ts
import http from 'http';

const PORT = 27487;
const VERUSD_PORT = 27486;
const VERUSD_HOST = 'localhost';

http.createServer(async (req, res) => {
  // CORS headers so browser accepts the response
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');

  // preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // read request body
  const body = await new Promise<string>((resolve) => {
    let data = '';
    req.on('data', (chunk: Buffer) => data += chunk);
    req.on('end', () => resolve(data));
  });

  // forward to verusd
  const options: http.RequestOptions = {
    hostname: VERUSD_HOST,
    port:     VERUSD_PORT,
    path:     '/',
    method:   'POST',
    headers: {
      'Content-Type':   'application/json',
      'Authorization':  req.headers.authorization ?? '',
      'Content-Length': Buffer.byteLength(body),
    },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode ?? 200, { 'Content-Type': 'application/json' });
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (e: Error) => {
    console.error('verusd error:', e.message);
    res.writeHead(502);
    res.end(JSON.stringify({ error: { message: e.message } }));
  });

  proxyReq.write(body);
  proxyReq.end();

}).listen(PORT, () => {
  console.log(`proxy running on http://localhost:${PORT} → verusd at ${VERUSD_HOST}:${VERUSD_PORT}`);
});