#!/usr/bin/env node
'use strict';
// UI validation only: real compiled upstream components and a captured core REST
// response. Auxiliary authentication/overview responses below are test scaffolding,
// not evidence about authentication, metrics or a deployed SmartDNS instance.
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const [outArg, apiArg, reportArg, mode] = process.argv.slice(2);
assert(!mode || mode === "--server-check" || mode === "--diagnostic-fixture", "unknown validation mode");
if (!outArg || !apiArg || !reportArg) throw Error('usage: test-browser.cjs WEBUI_OUT CAPTURED_API_JSON REPORT_DIRECTORY');
const out = fs.realpathSync(outArg);
const apiBody = fs.readFileSync(apiArg);
const rows = JSON.parse(apiBody).upstream_server_list;
const pools = rows.filter(r => r.pool_enabled);
const ordinary = rows.filter(r => !r.pool_enabled);
assert.equal(pools.length, 3);
assert.equal(ordinary.length, 1);
assert.equal(new Set(pools.map(r => r.service_id)).size, 3);
assert.equal(new Set(pools.map(r => r.server_type)).size, 1);
assert.equal(pools.filter(r => r.host === 'resolver.example').length, 2);
assert.equal(ordinary[0].ip, '127.0.0.9');
fs.mkdirSync(reportArg, { recursive: true });
const mime = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2', '.txt': 'text/plain' };
const auxiliary = {
  '/api/auth/check': {}, '/api/auth/logout': {},
  '/api/server/version': { smartdns: 'UI-fixture-only', smartdns_ui: 'UI-fixture-only' },
  '/api/stats/overview': { server_name: 'UI fixture', db_size: 0, startup_timestamp: 0 },
  '/api/stats/top/client': { client_top_list: [] },
  '/api/stats/top/domain': { domain_top_list: [] },
  '/api/stats/hourly-query-count': { hourly_query_count: [], query_timestamp: 0 },
  '/api/stats/daily-query-count': { daily_query_count: [], query_timestamp: 0 },
};
const errors = [], consoleMessages = [], requests = [], responses = [], requestFailures = [], artifactErrors = [], actions = [];
let upstreamReads = 0;
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  requests.push({ method: req.method, path: url.pathname, query: url.search, rsc: req.headers.rsc || null });
  res.on('finish', () => responses.push({ path: url.pathname, status: res.statusCode, type: res.getHeader('content-type') || null }));
  if (url.pathname === '/api/upstream-server') {
    upstreamReads++;
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(apiBody); return;
  }
  if (Object.hasOwn(auxiliary, url.pathname)) {
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(auxiliary[url.pathname])); return;
  }
  let relative;
  try { relative = decodeURIComponent(url.pathname).replace(/^\/+/, ''); }
  catch { res.writeHead(400); res.end(); return; }
  const candidate = path.resolve(out, relative || 'index.html');
  if (!candidate.startsWith(out + path.sep)) { res.writeHead(403); res.end(); return; }
  const file = [candidate, candidate + '.html', path.join(candidate, 'index.html')]
    .find(f => fs.existsSync(f) && fs.statSync(f).isFile());
  if (!file) { res.writeHead(404); res.end(); return; }
  if (!fs.realpathSync(file).startsWith(out + path.sep)) { res.writeHead(403); res.end(); return; }
  res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});
// Metrics are unrelated to this fixture. Refuse their optional websocket rather
// than fabricate performance samples or open a connection to a real instance.
server.on('upgrade', (_req, socket) => socket.destroy());
let browser, page;
let stage = 'initialization';
async function capture(label) {
  if (!page || page.isClosed()) return;
  for (const [name, action] of [
    ['html', () => page.content().then(text => fs.writeFileSync(path.join(reportArg, label + '.html'), text))],
    ['png', () => page.screenshot({ path: path.join(reportArg, label + '.png'), fullPage: true, timeout: 3000, animations: 'disabled' })],
    ['state', async () => fs.writeFileSync(path.join(reportArg, label + '.state.json'), JSON.stringify({ url: page.url(), title: await page.title(), stage }, null, 2))],
  ]) {
    try { await action(); } catch (error) { artifactErrors.push(`${label}.${name}: ${error}`); }
  }
}
(async () => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  if (mode === '--server-check') {
    // Exercise the actual static/API serving code without starting any browser.
    for (const [route, type] of [['/dashboard', 'text/html'], ['/dashboard/upstream-servers', 'text/html'],
      ['/dashboard/upstream-servers.txt', 'text/plain'], ['/dashboard/upstream-servers/__next._tree.txt', 'text/plain']]) {
      const res = await fetch(base + route); assert.equal(res.status, 200); assert.equal(res.headers.get('content-type'), type);
      assert((await res.text()).length > 0);
    }
    const res = await fetch(base + '/api/upstream-server'); assert.deepEqual(Buffer.from(await res.arrayBuffer()), apiBody);
    assert.equal((await fetch(base + '/%ZZ')).status, 400);
    assert.equal((await fetch(base + '/%2e%2e%2foutside')).status, 403);
    fs.writeFileSync(path.join(reportArg, 'server-check.json'), JSON.stringify({ passed: true, browser_run: false, requests, responses }, null, 2));
    return;
  }
  const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
  browser = await chromium.launch({ headless: true, chromiumSandbox: true,
    ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}) });
  const context = await browser.newContext({ viewport: { width: 1600, height: 1100 }, locale: 'en-US', serviceWorkers: 'block' });
  assert.equal(typeof context.routeWebSocket, 'function', 'existing Playwright must support websocket routing');
  await context.routeWebSocket('**', ws => {
    if (!ws.url().startsWith(base.replace('http:', 'ws:') + '/')) errors.push(`external websocket blocked: ${ws.url()}`);
    ws.close();
  });
  await context.addInitScript(() => {
    localStorage.setItem('custom-auth-token', JSON.stringify({ token: 'isolated-ui-fixture', expiresAt: Date.now() + 600000 }));
    localStorage.setItem('i18nextLng', 'en');
  });
  // The bundle must remain isolated; no production API, CDN or DNS endpoint is
  // needed. Unexpected external requests are aborted and recorded.
  await context.route('**/*', route => {
    if (route.request().url().startsWith(base + '/')) return route.continue();
    errors.push(`external request blocked: ${route.request().url()}`); return route.abort();
  });
  page = await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('requestfailed', request => requestFailures.push({ url: request.url(), failure: request.failure() }));
  page.on('pageerror', error => errors.push(String(error)));
  page.on('console', msg => {
    consoleMessages.push({ type: msg.type(), text: msg.text() });
    if (/same key|unique.*key|duplicate.*key/i.test(msg.text())) errors.push(msg.text());
  });
  stage = 'dashboard bootstrap';
  await page.goto(base + '/dashboard', { waitUntil: 'domcontentloaded' });
  // The pinned dashboard mounts metrics/charts, NOT UpStreamServersCard. Use
  // its real sidebar route; never mount a dead component or inject React state.
  const upstreamNav = page.locator('nav a[href="/dashboard/upstream-servers"]:visible');
  await upstreamNav.first().waitFor();
  await capture('dashboard-ready');
  stage = 'native upstream route navigation';
  await Promise.all([
    page.waitForResponse(r => r.url() === base + '/api/upstream-server' && r.status() === 200),
    upstreamNav.first().click().then(() => page.waitForURL('**/dashboard/upstream-servers')),
  ]);
  async function assertRows() {
    await page.getByText(pools[0].endpoint_ips.join(', '), { exact: true }).waitFor();
    assert.equal(await page.locator('tbody tr').count(), 4);
    for (const row of pools) {
      const cell = page.getByText(row.endpoint_ips.join(', '), { exact: true });
      assert.equal(await cell.count(), 1);
      const tr = cell.locator('xpath=ancestor::tr');
      assert((await tr.textContent()).includes(row.host));
      if (row.diagnostics) assert.equal(await tr.getByRole('button', { name: /诊断|Diagnostics/ }).count(), 1);
      if (row.response_statistics) {
        const rate=row.response_statistics.success_rate;
        assert((await tr.textContent()).includes(typeof rate==='number'?rate.toFixed(2)+' %':'—'));
      }
    }
    const normal = page.locator('tbody tr').filter({ hasText: '127.0.0.9' });
    assert.equal(await normal.count(), 1);
    assert((await normal.textContent()).includes('5309'));
    assert.equal(await page.locator('tbody a[href*="client="]').count(), 0,
      'native details table must not turn service/IP lists into client filters');
  }
  stage = 'initial table assertions';
  await assertRows();
  await capture('upstream-initial');
  if (pools[0].diagnostics) {
    stage = 'actual service diagnostic disclosure';
    const tr = page.getByText(pools[0].endpoint_ips.join(', '), { exact: true }).locator('xpath=ancestor::tr');
    const button = tr.getByRole('button', { name: /诊断|Diagnostics/ });
    await button.click();
    const dialog = page.getByRole('dialog');
    const section = dialog.getByRole('tabpanel');
    await section.waitFor({ state: 'visible' });
    assert.equal(await dialog.getByRole('tab').count(), 4);
    async function checkCardSeparation() {
      const appearance=await section.locator('.MuiPaper-outlined').first().evaluate(el=>{
        const card=getComputedStyle(el), backdrop=getComputedStyle(el.closest('.MuiDialogContent-root'));
        return {border:card.borderTopColor,width:Number.parseFloat(card.borderTopWidth),surface:card.backgroundColor,backdrop:backdrop.backgroundColor};
      });
      assert(appearance.width>=1,'cards need a real visible border');
      assert.notEqual(appearance.surface,appearance.backdrop,'card surface and backdrop must differ');
      const alpha=appearance.border.match(/rgba\([^,]+,[^,]+,[^,]+,\s*([.\d]+)\)/);
      if(alpha) assert(Number(alpha[1])>=.2,'card outline must be stronger than a faint default divider');
      return appearance;
    }
    await checkCardSeparation();
    const desktopFont=await dialog.evaluate(el=>Number.parseFloat(getComputedStyle(el).fontSize));
    assert(desktopFont<=14,'desktop diagnostic body must stay compact');
    await dialog.getByRole('tab').nth(1).click();
    assert.match(await section.textContent(), /连接地址族|Transport family/);
    await capture('upstream-backends-and-latency');
    await dialog.getByRole('tab').nth(2).click();
    if (mode==='--diagnostic-fixture') {
      assert.equal(pools[0].response_statistics.success_rate,99.15);
      assert.equal(await section.locator('summary').filter({hasText:/HTTP 429/}).count(),1);
      const burst=section.locator('details').filter({has:page.locator('summary').filter({hasText:/HTTP 429/})}).first();
      await burst.locator('summary').click();
      assert.equal(await burst.getByText(/request-\d+\.example/).count(),14);
      assert.match(await burst.textContent(),/2026/);
      assert.equal(await burst.getByText('request-0.example · A · #0',{exact:true}).count(),1);
      assert.match(await burst.textContent(),/固定冷却|Fixed cooldown/);
      assert(!/0 \/ 1000 ms/.test(await burst.textContent()),'cooldown must not be formatted as measured response elapsed');
      await section.getByRole('button',{name:/^DNS 响应$|^DNS responses$/}).click();
      assert.equal(await section.locator('summary').filter({hasText:/HTTP 429/}).count(),0);
      assert.match(await section.textContent(),/DNS 响应未被接受|DNS response not accepted/);
      await section.getByRole('button',{name:/^全部$|^All$/}).click();
    }
    await capture('upstream-recent-events');
    await dialog.getByRole('tab').nth(3).click();
    assert((await section.textContent()).includes(pools[0].diagnostics.cooldown_ms + ' ms'));
    assert.match(await section.textContent(), /全局客户端线程|Global client thread/);
    const bounds = await dialog.boundingBox();
    assert(bounds && bounds.width >= 500 && bounds.x >= 0 && bounds.x + bounds.width <= 1600);
    const contentBounds = await section.evaluate(el => ({content: el.scrollWidth, viewport: el.clientWidth}));
    assert(contentBounds.content <= contentBounds.viewport + 1, 'diagnostic content must not be clipped by its cell');
    await capture('upstream-diagnostics');
    await page.emulateMedia({colorScheme:'dark'});
    await page.waitForFunction(()=>document.documentElement.classList.contains('dark'));
    await checkCardSeparation();
    await capture('upstream-diagnostics-dark');
    await page.emulateMedia({colorScheme:'light'});
    await page.waitForFunction(()=>document.documentElement.classList.contains('light'));
    await dialog.getByRole('button', { name: /关闭|Close/ }).click();
    await dialog.waitFor({ state: 'hidden' });
    await page.setViewportSize({ width: 390, height: 844 });
    await button.click();
    await dialog.waitFor({ state: 'visible' });
    const mobile = await dialog.boundingBox();
    assert(mobile && mobile.x >= 0 && mobile.x + mobile.width <= 390);
    const mobileFont=await dialog.evaluate(el=>Number.parseFloat(getComputedStyle(el).fontSize));
    assert(mobileFont<=desktopFont&&mobileFont>=12,'mobile font must adapt while remaining readable');
    for (let tab=0;tab<4;tab++) {
      await dialog.getByRole('tab').nth(tab).click();
      const mobileContent = await section.evaluate(el => ({content: el.scrollWidth, viewport: el.clientWidth}));
      assert(mobileContent.content <= mobileContent.viewport + 1, 'each mobile panel must remain readable without horizontal clipping');
      if (tab===2) await capture('upstream-events-mobile');
    }
    await capture('upstream-diagnostics-mobile');
    await dialog.getByRole('button', { name: /关闭|Close/ }).click();
    await dialog.waitFor({ state: 'hidden' });
    await page.setViewportSize({ width: 1600, height: 1100 });
  }
  if(ordinary[0].diagnostics) {
    stage='ordinary upstream real diagnostics';
    const tr=page.locator('tbody tr').filter({hasText:'127.0.0.9'});
    await tr.getByRole('button',{name:/诊断|Diagnostics/}).click();
    const dialog=page.getByRole('dialog'); await dialog.waitFor({state:'visible'});
    assert.match(await dialog.textContent(),/单节点上游诊断|Endpoint diagnostics/);
    for(let tab=0;tab<4;tab++) {
      await dialog.getByRole('tab').nth(tab).click();
      const panel=dialog.getByRole('tabpanel');
      if(tab===1) assert.match(await panel.textContent(),/127\.0\.0\.9/);
      if(tab===3) {
        assert(!/两族建连间隔|Family connection delay/.test(await panel.textContent()),'ordinary endpoints must not pretend to use pool connection racing');
        assert.match(await panel.textContent(),/HTTP 固定冷却|Fixed HTTP cooldown/);
        assert(!/故障等待|failure wait/.test(await panel.textContent()),'ordinary native retries do not use the pool failure interval');
      }
    }
    await capture('ordinary-upstream-diagnostics');
    await dialog.getByRole('button',{name:/关闭|Close/}).click();
    await dialog.waitFor({state:'hidden'});
  }
  stage = 'locate real toolbar refresh';
  // Production MUI deliberately omits SvgIcon data-testid. Use the actual
  // Tooltip-provided accessible name, never a development-only icon marker.
  const refresh = page.getByRole('button', { name: 'Refresh Data', exact: true });
  assert.equal(await refresh.count(), 1, 'one real accessible refresh button');
  await refresh.waitFor({ state: 'visible' });
  assert(await refresh.isEnabled(), 'real refresh button is enabled');
  stage = 'real toolbar refresh';
  const beforeRefresh = upstreamReads;
  const refreshAction = { name: 'toolbar refresh click', completed: false };
  actions.push(refreshAction);
  await Promise.all([
    page.waitForResponse(r => r.url() === base + '/api/upstream-server' && r.status() === 200),
    refresh.click().then(() => { refreshAction.completed = true; }).catch(error => {
      refreshAction.error = String(error); throw error;
    }),
  ]);
  assert(upstreamReads > beforeRefresh, 'actual refresh produced a new API request');
  await assertRows();
  await capture('upstream-refreshed');
  stage = 'direct native route reload';
  const beforeReload = upstreamReads;
  const reloadAction = { name: 'native route reload', completed: false };
  actions.push(reloadAction);
  await Promise.all([
    page.waitForResponse(r => r.url() === base + '/api/upstream-server' && r.status() === 200),
    page.reload({ waitUntil: 'domcontentloaded' }).then(() => { reloadAction.completed = true; }).catch(error => {
      reloadAction.error = String(error); throw error;
    }),
  ]);
  assert(upstreamReads > beforeReload, 'actual reload produced a new API request');
  await assertRows();
  await capture('upstream-reloaded');
  assert.deepEqual(errors, []);
  fs.writeFileSync(path.join(reportArg, 'result.json'), JSON.stringify({
    passed: true, api_sha256: crypto.createHash('sha256').update(apiBody).digest('hex'),
    service_ids: pools.map(r => r.service_id), upstreamReads, requests,
    consoleMessages, errors, responses, requestFailures, artifactErrors, actions, stage,
    legacy_overview: 'UpStreamServersCard is not mounted by the pinned dashboard and was not runtime-tested.', note: 'Actual compiled components + captured core REST; auxiliary auth/metrics are not under test.'
  }, null, 2) + '\n');
})().catch(async error => {
  await capture('failure');
  fs.writeFileSync(path.join(reportArg, 'failure.json'), JSON.stringify({ error: String(error), stage, url: page && !page.isClosed() ? page.url() : null, errors, consoleMessages, requests, responses, requestFailures, artifactErrors, actions, upstreamReads }, null, 2) + '\n');
  process.exitCode = 1;
}).finally(async () => {
  if (browser) await browser.close();
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
});
