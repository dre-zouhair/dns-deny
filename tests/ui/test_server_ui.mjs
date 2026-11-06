// Real Rust backend + Chrome: no mocked API or browser-side page controllers.
// Build first: cargo build -p api --example web_fixture
import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { browser, controls, waitFor, pause } from './browser.mjs';
import { server } from './server.mjs';

const app = await server();
const page = await browser();
const ui = controls(page);
let checks = 0;
const check = async (name, work) => { await work(); console.log(`PASS ${name}`); checks++; };
async function navigate(path, selector = '#page-content') {
  await page.command('Page.navigate', { url: app.base + path });
  await waitFor(page, `location.href === ${JSON.stringify(app.base + path)} && document.querySelector(${JSON.stringify(selector)})`);
  await pause(80);
}
async function submit(form, intent = 'save') {
  await page.evaluate(`document.querySelector(${JSON.stringify(form)}).requestSubmit(document.querySelector(${JSON.stringify(`${form} [name="intent"][value="${intent}"]`)}))`);
}
const notice = section => waitFor(page, `document.querySelector(${JSON.stringify(section + ' .ui-notice')})`);
try {
  await check('native login issues a cookie without putting credentials in storage', async () => {
    await navigate('/login.html', '#login-form');
    await ui.input('#api-key-input', 'test-secret-key');
    await ui.submit('#login-form');
    await waitFor(page, `document.querySelector('#page-content')`);
    assert.equal(await page.evaluate(`document.cookie.includes('dns_deny_session')`), false);
    assert.equal(await page.evaluate(`Object.values(localStorage).some(v => v.includes('test-secret-key'))`), false);
  });
  for (const [path, section] of [
    ['/', 'overview-stats'], ['/lists.html', 'lists-remote'], ['/lists.html?tab=allowdeny', 'lists-allow'],
    ['/lists.html?tab=regex', 'lists-regex-deny'], ['/lists.html?tab=overview', 'lists-summary'],
    ['/services.html', 'services-apps'], ['/services.html?tab=autoblock', 'services-autoblock'],
    ['/services.html?tab=smartip', 'services-ips'], ['/services.html?tab=safesearch', 'services-safesearch'],
    ['/network.html', 'network-devices'], ['/network.html?tab=aliases', 'network-aliases'],
    ['/network.html?tab=localdns', 'network-records'], ['/config.html', 'config-main'],
    ['/config.html?tab=security', 'config-security'], ['/config.html?tab=diagnostics', 'config-diagnostics'],
    ['/doh.html', 'doh-encrypted'], ['/doh.html?tab=primary', 'doh-primary']
  ]) await check(`server renders ${path}`, async () => {
    await navigate(path, '#section-' + section);
    assert.equal(await page.evaluate(`document.body.textContent.includes('Could not render')`), false, app.logs);
    assert.deepEqual(await page.evaluate(`Array.from(document.scripts, s => s.getAttribute('src')?.replace(/\\?v=[0-9a-f]+$/, '')).filter(Boolean)`), ['/ui.js', '/vendor/datastar-1.0.4.js']);
  });
  await check('rule form morphs HTML, clears submitted input and preserves unrelated drafts', async () => {
    await navigate('/lists.html?tab=allowdeny');
    await ui.input('#add-deny [name=pattern]', 'draft.example');
    await ui.input('#add-allow [name=pattern]', 'allowed.example');
    await submit('#add-allow', 'add');
    await notice('#section-lists-allow');
    assert.equal(await page.evaluate(`document.querySelector('#add-allow [name=pattern]').value`), '');
    assert.equal(await page.evaluate(`document.querySelector('#add-deny [name=pattern]').value`), 'draft.example');
    assert.deepEqual(await (await app.api('/lists/allow')).json(), ['allowed.example']);
    assert.equal(await page.evaluate(`performance.getEntriesByType('resource').some(r => new URL(r.name).pathname.startsWith('/api/v1'))`), false);
    await ui.input('#add-deny [name=pattern]', 'allowed.example');
    await submit('#add-deny', 'add');
    await notice('#section-lists-deny');
    await waitFor(page, `!document.querySelector('#section-lists-allow table').textContent.includes('allowed.example')`);
    await ui.input('#add-deny [name=pattern]', 'keep-second-draft.example');
    await ui.input('#add-allow [name=pattern]', 'another.example');
    await submit('#add-allow', 'add');
    await waitFor(page, `document.querySelector('#section-lists-allow table').textContent.includes('another.example')`);
    assert.equal(await page.evaluate(`document.querySelector('#add-deny [name=pattern]').value`), 'keep-second-draft.example');
  });
  await check('invalid regex preserves input and returns an escaped server error', async () => {
    await navigate('/lists.html?tab=regex');
    await ui.input('#add-regex-deny [name=pattern]', '[');
    await submit('#add-regex-deny', 'add');
    await waitFor(page, `document.querySelector('#section-lists-regex-deny [role=alert]')`);
    assert.equal(await page.evaluate(`document.querySelector('#add-regex-deny [name=pattern]').value`), '[');
  });
  await check('alias HTML escapes stored user content', async () => {
    await navigate('/network.html?tab=aliases');
    await ui.input('#alias-form [name=identifier]', '192.0.2.10');
    await ui.input('#alias-form [name=name]', '<img src=x onerror=alert(1)>');
    await submit('#alias-form', 'add');
    await notice('#section-network-aliases');
    assert.equal(await page.evaluate(`document.querySelectorAll('#section-network-aliases img').length`), 0);
    assert.equal(await page.evaluate(`document.querySelector('#section-network-aliases').textContent.includes('<img src=x onerror=alert(1)>')`), true);
  });
  await check('stored Datastar attributes remain text and cannot execute expressions', async () => {
    const payload = '\"><div data-init="globalThis.__datastarInjected=1">injected</div>';
    await ui.input('#alias-form [name=identifier]', '192.0.2.11');
    await ui.input('#alias-form [name=name]', payload);
    await submit('#alias-form', 'add');
    await waitFor(page, `document.querySelector('#section-network-aliases').textContent.includes('globalThis.__datastarInjected')`);
    assert.equal(await page.evaluate(`document.querySelectorAll('#section-network-aliases [data-init]').length`), 0);
    assert.equal(await page.evaluate(`typeof globalThis.__datastarInjected`), 'undefined');
  });
  await check('custom app creation, device policies, schedules and SafeSearch save on the server', async () => {
    await navigate('/services.html');
    await ui.input('#custom-app-form [name=name]', 'Browser Fixture');
    await ui.input('#custom-app-form [name=wildcards]', '*.fixture.example');
    await submit('#custom-app-form', 'add');
    await notice('#section-services-apps');
    const apps = await (await app.api('/config/services')).json();
    assert.ok(apps.some(app => app.id === 'custom_browser_fixture'));
    await navigate('/network.html');
    await ui.input('#policy-1 [name=policy]', 'whitelist');
    await submit('#policy-1', 'policy');
    await notice('#section-network-devices');
    await ui.input('#schedule-form [name=ip]', '192.0.2.10');
    await ui.input('#schedule-form [name=start_time]', '08:00');
    await ui.input('#schedule-form [name=end_time]', '17:00');
    await submit('#schedule-form', 'add');
    await notice('#section-network-schedules');
    assert.equal((await (await app.api('/network/schedules')).json()).length, 1);
    await navigate('/services.html?tab=safesearch');
    await page.evaluate(`document.querySelector('#safesearch-form [name=enabled]').checked = true`);
    await submit('#safesearch-form');
    await notice('#section-services-safesearch');
    assert.equal((await (await app.api('/config/safesearch')).json()).enforce_safesearch, true);
  });
  await check('device timers pause, resume, and refresh after expiry', async () => {
    await navigate('/network.html');
    await ui.input('#device-pause-1 [name=seconds]', '300');
    await submit('#device-pause-1', 'pause');
    await waitFor(page, `document.querySelector('#device-pause-1 [value=resume]')`);
    let status = await (await app.api('/protection/status')).json();
    assert.ok(status.device_pauses['192.0.2.10'] > Date.now() / 1000);
    assert.equal(await page.evaluate(`document.querySelector('#section-network-devices').textContent.includes('Paused until')`), true);
    if (process.env.DEVICE_PAUSE_SCREENSHOT) {
      const { data } = await page.command('Page.captureScreenshot', {format:'png', captureBeyondViewport:true});
      await writeFile(process.env.DEVICE_PAUSE_SCREENSHOT, Buffer.from(data, 'base64'));
    }
    await submit('#device-pause-1', 'resume');
    await waitFor(page, `document.querySelector('#device-pause-1 [value=pause]')`);
    status = await (await app.api('/protection/status')).json();
    assert.deepEqual(status.device_pauses, {});
    const short = await app.api('/protection/pause', {method:'POST', body: JSON.stringify({scope:'device', id:'192.0.2.10', duration_secs:2})});
    assert.equal(short.status, 200);
    await navigate('/network.html');
    await waitFor(page, `document.querySelector('#device-pause-1 [value=pause]')`);
    status = await (await app.api('/protection/status')).json();
    assert.deepEqual(status.device_pauses, {});
  });
  await check('local DNS records validate and save through server forms', async () => {
    await navigate('/network.html?tab=localdns');
    await ui.input('#record-form [name=name]', 'printer.fixture');
    await ui.input('#record-form [name=value]', 'invalid-ip');
    await submit('#record-form', 'add');
    await waitFor(page, `document.querySelector('#section-network-records [role=alert]')`);
    await ui.input('#record-form [name=value]', '192.0.2.20');
    await submit('#record-form', 'add');
    await notice('#section-network-records');
    assert.ok((await (await app.api('/local-dns')).json()).some(record => record.name === 'printer.fixture'));
  });
  await check('mobile navigation works as a native disclosure', async () => {
    await page.command('Emulation.setDeviceMetricsOverride', {width: 820, height: 900, deviceScaleFactor: 1, mobile: false});
    await navigate('/');
    await ui.click('.mobile-menu summary');
    assert.equal(await page.evaluate(`document.querySelector('.mobile-menu').open`), true);
    assert.ok(await page.evaluate(`document.querySelector('.mobile-menu nav').getBoundingClientRect().height > 0`));
    await page.command('Emulation.setDeviceMetricsOverride', {width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false});
  });
  await check('static assets are versioned and cached safely', async () => {
    await navigate('/');
    const headers = await page.evaluate(`Promise.all(['/vendor/datastar-1.0.4.js', document.querySelector('link[rel=stylesheet]').getAttribute('href')].map(url => fetch(url).then(r => [r.status, r.headers.get('cache-control')])))`);
    assert.deepEqual(headers, [[200, 'public, max-age=31536000, immutable'], [200, 'no-cache']]);
    assert.match(await page.evaluate(`document.querySelector('link[rel=stylesheet]').getAttribute('href')`), /^\/styles\.css\?v=[0-9a-f]{12}$/);
  });
  await check('search forms, filter bars and badges keep their compact layout', async () => {
    await navigate('/services.html');
    const layout = await page.evaluate(`(() => {
      const search = document.querySelector('#section-services-apps .ui-search');
      const input = search.querySelector('.input').getBoundingClientRect(), button = search.querySelector('button').getBoundingClientRect();
      const badge = document.querySelector('#section-services-apps .badge').getBoundingClientRect();
      const card = document.querySelector('#section-services-apps .badge').closest('.card').getBoundingClientRect();
      return { sameRow: Math.abs(input.top - button.top) < 8, badgeNarrow: badge.width < card.width / 2,
        tabUnderline: getComputedStyle(document.querySelector('a.tab-pill')).textDecorationLine };
    })()`);
    assert.deepEqual(layout, { sameRow: true, badgeNarrow: true, tabUnderline: 'none' });
    await navigate('/livetail.html?mode=paused', '#query-rows');
    assert.equal(await page.evaluate(`(() => { const groups = [...document.querySelectorAll('.log-filter-group')].map(g => g.getBoundingClientRect().top); return groups.every(top => Math.abs(top - groups[0]) < 8); })()`), true);
  });
  await check('the protection menu stays open across its 5s status poll', async () => {
    await navigate('/');
    await ui.click('.ui-protection summary');
    assert.equal(await page.evaluate(`document.querySelector('.ui-protection').open`), true);
    await pause(5600);
    assert.equal(await page.evaluate(`document.querySelector('.ui-protection').open`), true);
  });
  await check('upstream draft edits stay local to the form until an atomic save', async () => {
    await navigate('/config.html');
    const original = await (await app.api('/config/upstreams')).json();
    await ui.input('#upstreams-form [name=address]', '9.9.9.9:53');
    await submit('#upstreams-form', 'add');
    await waitFor(page, `document.querySelectorAll('#upstreams-form [name=address]').length === 2`);
    assert.equal(await page.evaluate(`document.querySelector('#upstreams-form [name=address]').value`), '9.9.9.9:53');
    assert.deepEqual(await (await app.api('/config/upstreams')).json(), original);
    await ui.input('#upstreams-form [name=address]', 'invalid-address');
    await submit('#upstreams-form');
    await waitFor(page, `document.querySelector('#section-config-main [role=alert]')`);
    assert.deepEqual(await (await app.api('/config/upstreams')).json(), original);
    await ui.input('#upstreams-form [name=address]', '9.9.9.9:53');
    await submit('#upstreams-form');
    await notice('#section-config-main');
    assert.equal((await (await app.api('/config/upstreams')).json()).upstreams.length, 2);
  });
  await check('DoH pool draft and saved configuration use server actions', async () => {
    await navigate('/doh.html');
    const before = await (await app.api('/config/doh')).json();
    await ui.input('#doh-form [name=new_url]', 'https://example.com/dns-query');
    await submit('#doh-form', 'add');
    await waitFor(page, `Array.from(document.querySelectorAll('#doh-form [name=url]')).some(el => el.value === 'https://example.com/dns-query')`);
    assert.deepEqual(await (await app.api('/config/doh')).json(), before);
    await page.evaluate(`const form = document.querySelector('#doh-form'); const index = form.querySelectorAll('[name=url]').length - 1; form.requestSubmit(form.querySelector('[value="select:' + index + '"]'))`);
    await waitFor(page, `document.querySelector('#doh-form [name=active_url]').value === 'https://example.com/dns-query'`);
    await submit('#doh-form');
    await waitFor(page, `document.querySelector('#section-doh-encrypted .ui-notice')?.textContent.includes('saved')`);
    assert.ok((await (await app.api('/config/doh')).json()).doh_upstreams.includes('https://example.com/dns-query'));
  });
  await check('live HTML stream receives rows and pauses/resumes without clearing them', async () => {
    await navigate('/livetail.html', '#query-rows');
    await waitFor(page, `document.querySelector('#query-rows').children.length >= 3`);
    await ui.click('[data-on\\:click*="X-Stop-Live"]');
    await pause(250);
    const count = await page.evaluate(`document.querySelector('#query-rows').children.length`);
    await pause(400);
    assert.equal(await page.evaluate(`document.querySelector('#query-rows').children.length`), count);
    await page.evaluate(`Array.from(document.querySelectorAll('button')).find(el => el.textContent.trim() === 'Start Live').click()`);
    await waitFor(page, `document.querySelector('#query-rows').children.length > ${count}`);
    await waitFor(page, `document.querySelector('#query-rows').children.length === 500`);
    await pause(200);
    assert.equal(await page.evaluate(`document.querySelector('#query-rows').children.length`), 500);
    assert.equal(await page.evaluate(`document.querySelector('#query-rows').textContent.includes('live-xss-')`), true);
    assert.equal(await page.evaluate(`document.querySelectorAll('#query-rows img, #query-rows script, #query-rows [data-init]').length`), 0);
    assert.equal(await page.evaluate(`typeof globalThis.__logXss`), 'undefined');
  });
  await check('history filtering and pagination happen on the server', async () => {
    await navigate('/livetail.html?mode=history&verdict=Block', '#query-rows');
    assert.equal(await page.evaluate(`document.querySelector('#query-rows').children.length`), 100);
    await navigate('/livetail.html?mode=history&verdict=Block&page=3', '#query-rows');
    assert.equal(await page.evaluate(`document.querySelector('#query-rows').children.length`), 50);
    await ui.input('.log-filter-bar [name=q]', 'seed-249');
    await page.evaluate(`const form=document.querySelector('.log-filter-bar'); form.requestSubmit(form.querySelector('[value=history]'))`);
    await waitFor(page, `document.querySelector('#query-rows').children.length === 1`);
  });
  await check('untrusted query filters stay out of executable Datastar expressions', async () => {
    const payload = `');globalThis.__datastarInjected=1;//"><div data-init="globalThis.__datastarInjected=1"></div>&`;
    await navigate('/livetail.html?' + new URLSearchParams({ mode: 'live', q: payload }), '#query-rows');
    await waitFor(page, `document.querySelector('#section-queries-feed [role=status]').textContent.includes('connected')`);
    assert.equal(await page.evaluate(`new URL(document.querySelector('#section-queries-feed').dataset.streamUrl, location.origin).searchParams.get('q')`), payload);
    assert.equal(await page.evaluate(`Array.from(document.querySelectorAll('#section-queries-feed *')).some(el => Array.from(el.attributes).some(attr => (attr.name.startsWith('data-on:') || attr.name === 'data-init') && attr.value.includes('__datastarInjected')))`), false);
    await page.evaluate(`const form=document.querySelector('.log-filter-bar'); form.requestSubmit(form.querySelector('[value=history]'))`);
    await waitFor(page, `!document.querySelector('#query-stream') && document.querySelector('#query-rows').children.length === 0`);
    assert.equal(await page.evaluate(`document.querySelector('.log-filter-bar [name=q]').value`), payload);
    assert.equal(await page.evaluate(`typeof globalThis.__datastarInjected`), 'undefined');
  });
  await check('stored log and SVG chart payloads cannot create HTML or run scripts', async () => {
    await navigate('/livetail.html?mode=history&q=xss-fixture', '#query-rows');
    assert.equal(await page.evaluate(`document.querySelector('#query-rows').children.length`), 4);
    assert.equal(await page.evaluate(`document.querySelectorAll('#query-rows img, #query-rows svg, #query-rows script, #query-rows [data-init]').length`), 0);
    assert.equal(await page.evaluate(`typeof globalThis.__logXss`), 'undefined');
    await navigate('/');
    assert.equal(await page.evaluate(`document.querySelectorAll('svg img, svg script, svg [data-init], svg [onload]').length`), 0);
    assert.equal(await page.evaluate(`document.querySelector('#section-overview-stats').textContent.includes('xss-fixture')`), true);
    assert.equal(await page.evaluate(`typeof globalThis.__logXss`), 'undefined');
  });
  await check('native form add/search and upstream drafts work with scripts disabled', async () => {
    await page.command('Emulation.setScriptExecutionDisabled', { value: true });
    await navigate('/lists.html?tab=allowdeny');
    await ui.input('#add-deny [name=pattern]', 'native.example');
    await submit('#add-deny', 'add');
    await waitFor(page, `document.querySelector('#section-lists-deny')?.textContent.includes('native.example')`);
    await ui.input('#section-lists-deny .ui-search [name=q]', 'native');
    await ui.submit('#section-lists-deny .ui-search');
    await waitFor(page, `location.pathname === '/lists.html' && location.search.includes('q=native')`);
    await navigate('/config.html');
    await submit('#upstreams-form', 'add');
    await waitFor(page, `document.querySelectorAll('#upstreams-form [name=address]').length === 3`);
    await page.command('Emulation.setScriptExecutionDisabled', { value: false });
  });
  await check('API token card shows a one-time token that replaces the password for /api/v1', async () => {
    await navigate('/config.html?tab=security');
    await submit('#api-token-generate', 'generate');
    await notice('#section-config-api-token');
    const token = await page.evaluate(`document.querySelector('#section-config-api-token [data-copy]').dataset.copy`);
    assert.match(token, /^[0-9a-f]{64}$/);
    assert.equal((await app.api('/config', { headers: { Authorization: `Bearer ${token}` } })).status, 200);
    assert.equal((await app.api('/config')).status, 401);
    await page.evaluate(`window.confirm = () => true`);
    await submit('#api-token-revoke', 'revoke');
    await waitFor(page, `!document.querySelector('#api-token-revoke')`);
    assert.equal((await app.api('/config')).status, 200);
  });
  await check('password errors preserve input; successful rotation renews browser cookie', async () => {
    await navigate('/config.html?tab=security');
    await ui.input('#password-form [name=current_password]', 'test-secret-key');
    await ui.input('#password-form [name=new_password]', 'new-browser-password');
    await ui.input('#password-form [name=confirm_password]', 'different-password');
    await submit('#password-form');
    await waitFor(page, `document.querySelector('#section-config-security [role=alert]')`);
    assert.equal(await page.evaluate(`document.querySelector('#password-form [name=new_password]').value`), 'new-browser-password');
    await ui.input('#password-form [name=confirm_password]', 'new-browser-password');
    await submit('#password-form');
    await notice('#section-config-security');
    assert.equal(await page.evaluate(`document.querySelector('#password-form [name=new_password]').value`), '');
    assert.equal(await page.evaluate(`fetch('/ui/auth/session').then(r => r.status)`), 204);
    assert.equal((await app.api('/config')).status, 401);
  });
  await navigate('/');
  const screenshot = process.env.UI_SCREENSHOT;
  if (screenshot) {
    const { data } = await page.command('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    await writeFile(screenshot, Buffer.from(data, 'base64'));
  }
  await check('revoked sessions stop an open live stream and return to sign-in', async () => {
    await navigate('/livetail.html', '#query-rows');
    await waitFor(page, `document.querySelector('#query-rows').children.length > 0`);
    await page.evaluate(`fetch('/ui/auth/logout', {method:'POST'})`);
    await waitFor(page, `location.pathname === '/login.html' && document.querySelector('#login-form')`);
  });
  assert.deepEqual(page.errors, []);
  assert.equal(app.logs.includes('Dashboard render failed'), false, app.logs);
  console.log(`${checks} browser checks passed`);
} catch (error) {
  console.error('Page:', await page.evaluate(`document.body.textContent.slice(-2500)`));
  console.error('Server:', app.logs);
  throw error;
} finally { await page.close(); await app.close(); }
