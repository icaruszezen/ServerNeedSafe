import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const webDir = path.resolve(__dirname, '..');
const repoRoot = path.resolve(webDir, '..');
const distDir = path.resolve(webDir, 'dist');

const VIEWPORTS = [
  { name: 'mobile-320', width: 320, height: 568, isMobile: true, hasTouch: true },
  { name: 'mobile-375', width: 375, height: 812, isMobile: true, hasTouch: true },
  { name: 'mobile-390', width: 390, height: 844, isMobile: true, hasTouch: true },
  { name: 'mobile-412', width: 412, height: 915, isMobile: true, hasTouch: true },
  { name: 'tablet-768', width: 768, height: 1024, isMobile: true, hasTouch: true },
  { name: 'tablet-820', width: 820, height: 1180, isMobile: false, hasTouch: true },
  { name: 'landscape-844x390', width: 844, height: 390, isMobile: false, hasTouch: true },
  { name: 'desktop-1440', width: 1440, height: 940, isMobile: false, hasTouch: false },
];

async function startHarness() {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sns-e2e-bin-'));
  const binPath = path.join(binDir, 'sns-e2e-harness');
  try {
    execFileSync('go', ['build', '-o', binPath, './web/e2e/harness'], {
      cwd: repoRoot,
      stdio: ['ignore', 'inherit', 'inherit'],
    });
  } catch (err) {
    fs.rmSync(binDir, { recursive: true, force: true });
    throw err;
  }

  const proc = spawn(binPath, ['-dist', distDir], {
    cwd: repoRoot,
    env: {
      ...process.env,
      NO_PROXY: '127.0.0.1,localhost,*',
      no_proxy: '127.0.0.1,localhost,*',
      HTTP_PROXY: '',
      HTTPS_PROXY: '',
      http_proxy: '',
      https_proxy: '',
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stderrLog = '';
  proc.stderr.on('data', (d) => {
    stderrLog += d.toString();
  });

  let info;
  try {
    info = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Harness startup timed out. Stderr:\n${stderrLog}`));
      }, 30000);

      const rl = readline.createInterface({ input: proc.stdout });
      rl.once('line', (line) => {
        clearTimeout(timer);
        try {
          resolve(JSON.parse(line));
        } catch (err) {
          reject(new Error(`Failed to parse harness JSON "${line}": ${err}`));
        }
      });

      proc.once('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`Harness exited prematurely (code=${code}). Stderr:\n${stderrLog}`));
      });
    });
  } catch (err) {
    try {
      proc.kill('SIGKILL');
    } catch {
      // ignore
    }
    fs.rmSync(binDir, { recursive: true, force: true });
    throw err;
  }

  const stop = async () => {
    if (proc.exitCode === null) {
      try {
        proc.stdin.end();
        proc.kill('SIGTERM');
      } catch {
        // ignore
      }
      await new Promise((resolve) => {
        const killTimer = setTimeout(() => {
          try {
            proc.kill('SIGKILL');
          } catch {
            // ignore
          }
          resolve();
        }, 4000);
        proc.once('exit', () => {
          clearTimeout(killTimer);
          resolve();
        });
      });
    }
    if (info?.temp_dir) {
      fs.rmSync(info.temp_dir, { recursive: true, force: true });
    }
    fs.rmSync(binDir, { recursive: true, force: true });
  };

  return { info, stop };
}

async function assertNoHorizontalOverflow(page, contextLabel) {
  const metrics = await page.evaluate(() => {
    const docEl = document.documentElement;
    const body = document.body;
    const vw = window.innerWidth;
    const docScrollW = docEl.scrollWidth;

    const pageBodyLeaks = [];
    for (const pb of document.querySelectorAll('.page-body')) {
      const st = window.getComputedStyle(pb);
      if (st.display === 'none' || st.visibility === 'hidden') continue;
      if (pb.clientWidth > 0 && pb.scrollWidth > pb.clientWidth + 1) {
        const innerOffenders = [];
        const pbRect = pb.getBoundingClientRect();
        for (const child of pb.querySelectorAll('*')) {
          const cs = window.getComputedStyle(child);
          if (cs.display === 'none' || cs.visibility === 'hidden') continue;
          const cr = child.getBoundingClientRect();
          if (cr.width > 0 && cr.right > pbRect.right + 1.5) {
            innerOffenders.push({
              tag: child.tagName.toLowerCase(),
              cls: typeof child.className === 'string' ? child.className.slice(0, 50) : '',
              right: Math.round(cr.right),
              pbRight: Math.round(pbRect.right),
            });
            if (innerOffenders.length >= 4) break;
          }
        }
        pageBodyLeaks.push({
          scrollWidth: pb.scrollWidth,
          clientWidth: pb.clientWidth,
          innerOffenders,
        });
      }
    }

    const offenders = [];
    if (docScrollW > vw + 1) {
      for (const el of document.querySelectorAll('*')) {
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') continue;
        const r = el.getBoundingClientRect();
        if (r.width > 0 && r.right > vw + 1.5) {
          offenders.push({
            tag: el.tagName.toLowerCase(),
            id: el.id || '',
            cls: typeof el.className === 'string' ? el.className.slice(0, 60) : '',
            right: Math.round(r.right * 10) / 10,
            width: Math.round(r.width * 10) / 10,
          });
          if (offenders.length >= 6) break;
        }
      }
    }
    return {
      vw,
      docScrollW,
      bodyScrollW: body ? body.scrollWidth : 0,
      pageBodyLeaks,
      offenders,
    };
  });

  assert.ok(
    metrics.docScrollW <= metrics.vw + 1,
    `Horizontal overflow detected in [${contextLabel}]: scrollWidth=${metrics.docScrollW} > innerWidth=${metrics.vw}; offenders=${JSON.stringify(metrics.offenders)}`
  );
  assert.deepEqual(
    metrics.pageBodyLeaks,
    [],
    `Unmasked .page-body horizontal overflow detected in [${contextLabel}]: ${JSON.stringify(metrics.pageBodyLeaks)}`
  );
}

async function assertElementInViewport(page, selector, label) {
  await page
    .waitForFunction(
      (sel) => {
        const el = document.querySelector(sel);
        if (!el) return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.left >= -1 && r.right <= window.innerWidth + 1.5;
      },
      selector,
      { timeout: 2000 }
    )
    .catch(() => {});

  const box = await page.locator(selector).first().boundingBox();
  assert.ok(box, `Expected ${selector} to be visible in [${label}]`);
  const vw = page.viewportSize().width;
  assert.ok(
    box.x >= -1 && box.x + box.width <= vw + 1.5,
    `Element ${selector} overflows horizontally in [${label}]: x=${box.x}, width=${box.width}, vw=${vw}`
  );
}

async function assertMobileInputsFontSizeAtLeast16(page, contextLabel) {
  const violations = await page.evaluate(() => {
    if (window.innerWidth > 768) return [];
    const bad = [];
    const candidates = document.querySelectorAll(
      'input:not([type="checkbox"]):not([type="radio"]):not([type="hidden"]):not([type="file"]):not(.xterm-helper-textarea), select, textarea:not(.xterm-helper-textarea)'
    );
    for (const el of candidates) {
      const st = window.getComputedStyle(el);
      if (st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity) === 0) {
        continue;
      }
      const r = el.getBoundingClientRect();
      if (r.width <= 0 || r.height <= 0) continue;
      const fsPx = parseFloat(st.fontSize);
      if (Number.isFinite(fsPx) && fsPx < 16) {
        bad.push({
          tag: el.tagName.toLowerCase(),
          id: el.id || '',
          cls: typeof el.className === 'string' ? el.className.slice(0, 60) : '',
          placeholder: el.getAttribute('placeholder') || '',
          fontSize: st.fontSize,
        });
      }
    }
    return bad;
  });

  assert.deepEqual(
    violations,
    [],
    `Expected all visible mobile inputs/selects/textareas >= 16px in [${contextLabel}], violations: ${JSON.stringify(
      violations
    )}`
  );
}

async function navigateSection(page, navBtnId) {
  const vw = page.viewportSize().width;
  if (vw <= 768) {
    const sidebarOpen = await page.locator('#app-sidebar.mobile-open').count();
    if (!sidebarOpen) {
      await page.click('#mobile-menu-toggle-btn');
      await page.waitForSelector('#app-sidebar.mobile-open', { state: 'visible' });
    }
    await page.click(navBtnId);
    await page.waitForSelector('#app-sidebar.mobile-open', { state: 'hidden' });
  } else {
    await page.click(navBtnId);
  }
}

async function runSuite() {
  console.log('[e2e] Building & starting isolated ServerNeedSafe + SSHv2/SFTP + OpenAI SSE harness...');
  const { info, stop } = await startHarness();
  let browser;

  const runtimeErrors = [];
  const cspViolations = [];

  try {
    browser = await chromium.launch({
      executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium',
      headless: true,
      args: ['--no-proxy-server', '--no-sandbox', '--disable-dev-shm-usage'],
    });

    const context = await browser.newContext({
      viewport: { width: 390, height: 844 },
      deviceScaleFactor: 2,
      hasTouch: true,
    });

    const page = await context.newPage();
    page.on('pageerror', (err) => {
      runtimeErrors.push(`pageerror: ${err.message}`);
    });
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        runtimeErrors.push(`console.error: ${msg.text()}`);
      }
    });
    await page.exposeFunction('__recordCspViolation', (uri, directive) => {
      cspViolations.push(`${directive}: ${uri}`);
    });
    await page.addInitScript(() => {
      document.addEventListener('securitypolicyviolation', (e) => {
        // @ts-ignore
        window.__recordCspViolation?.(e.blockedURI, e.violatedDirective);
      });
    });

    // =========================================================================
    // 1. AuthGate Uninitialized Setup, Restore Mode & Dynamic Theme Meta Across 8 Viewports
    // =========================================================================
    console.log('[e2e] 1/8 Verifying AuthGate across 8 viewports (320px..1440px, Light & Dark + theme-color + >=16px inputs)...');
    await page.goto(info.base_url, { waitUntil: 'networkidle' });
    await page.waitForSelector('#auth-gate-card', { state: 'visible', timeout: 20000 });

    for (const vp of VIEWPORTS) {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      await assertNoHorizontalOverflow(page, `AuthGate-Setup-${vp.name}-light`);
      await assertElementInViewport(page, '#auth-gate-card', `AuthGate-${vp.name}`);
      await assertElementInViewport(page, '#auth-submit-btn', `AuthGate-Submit-${vp.name}`);

      if (vp.width <= 768) {
        await assertMobileInputsFontSizeAtLeast16(page, `AuthGate-${vp.name}`);
      }
    }

    // Switch to dark mode & verify dynamic meta[name="theme-color"] sync + Restore mode on ultra-narrow 320px
    await page.setViewportSize({ width: 320, height: 568 });
    const lightThemeAttr = await page.evaluate(() =>
      document.documentElement.getAttribute('data-theme')
    );
    const metaBefore = await page.evaluate(() =>
      document.querySelector('meta[name="theme-color"]')?.getAttribute('content')
    );
    assert.equal(
      metaBefore,
      lightThemeAttr === 'light' ? '#f5f6f8' : '#0b0d11',
      'Expected initial meta[name="theme-color"] to match data-theme'
    );
    await page.click('#auth-theme-toggle-btn');
    const metaAfter = await page.evaluate(() =>
      document.querySelector('meta[name="theme-color"]')?.getAttribute('content')
    );
    assert.equal(
      metaAfter,
      lightThemeAttr === 'light' ? '#0b0d11' : '#f5f6f8',
      'Expected meta[name="theme-color"] to update dynamically on theme toggle'
    );
    await page.click('#auth-tab-restore');
    await assertNoHorizontalOverflow(page, 'AuthGate-Restore-320-dark');
    const restoreBtns320 = await page.$$eval('#auth-gate-card button', (btns) =>
      btns.map((b) => {
        const r = b.getBoundingClientRect();
        return { text: b.textContent?.trim(), left: r.left, right: r.right };
      })
    );
    for (const b of restoreBtns320) {
      assert.ok(
        b.left >= -0.5 && b.right <= 320.5,
        `Expected AuthGate button "${b.text}" inside 320px viewport, got ${JSON.stringify(b)}`
      );
    }
    await page.click('#auth-tab-primary');

    // =========================================================================
    // 2. Real Zero-Knowledge WASM Vault Setup & Server/Keychain/Monitor/AI Data
    // =========================================================================
    console.log('[e2e] 2/8 Initializing Zero-Knowledge Vault & provisioning live SSH nodes...');
    await page.setViewportSize({ width: 390, height: 844 });
    const masterPass = 'StrongZeroKnowledge#2026';
    await page.fill('#admin-password-input', masterPass);
    await page.fill('#admin-password-confirm', masterPass);
    await page.click('#auth-submit-btn');
    await page.waitForSelector('#authenticated-app-shell', { state: 'visible', timeout: 25000 });
    await assertNoHorizontalOverflow(page, 'Servers-Empty-390');
    await assertMobileInputsFontSizeAtLeast16(page, 'Servers-Empty-390');

    // Add Server 1 (Edge Gateway) via mobile bottom-sheet modal
    await page.click('#add-server-btn');
    await page.waitForSelector('#server-form-modal', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'AddServerModal-390');
    await assertElementInViewport(page, '#server-form-modal', 'AddServerModal-390');
    await assertMobileInputsFontSizeAtLeast16(page, 'AddServerModal-390');

    const modalFieldCols = await page.$eval('#server-form-modal .field-row', (el) =>
      window.getComputedStyle(el).gridTemplateColumns.trim().split(/\s+/).length
    );
    assert.equal(modalFieldCols, 1, 'Expected single-column .field-row in modal at 390px');

    // Verify custom searchable group dropdown shows ALL groups even when default group is pre-filled
    await page.click('#srv-group-input-toggle');
    await page.waitForSelector('#srv-group-input-listbox', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'AddServerModal-GroupDropdown-390');
    const initialGroupOptions = await page.$$eval(
      '#srv-group-input-listbox [role="option"]',
      (els) => els.map((el) => (el.textContent || '').trim())
    );
    assert.ok(
      initialGroupOptions.length >= 4,
      `Expected all default groups visible on dropdown open even with pre-filled value, got ${JSON.stringify(initialGroupOptions)}`
    );
    await page.click('#srv-group-input-listbox [role="option"]:has-text("核心数据库")');
    await page.waitForSelector('#srv-group-input-listbox', { state: 'hidden' });
    assert.equal(await page.inputValue('#srv-group-input'), '核心数据库');
    await page.click('#srv-group-input-toggle');
    await page.waitForSelector('#srv-group-input-listbox', { state: 'visible' });
    await page.click('#srv-group-input-listbox [role="option"]:has-text("生产环境")');
    await page.waitForSelector('#srv-group-input-listbox', { state: 'hidden' });
    assert.equal(await page.inputValue('#srv-group-input'), '生产环境');

    await page.fill('#srv-name-input', '香港边缘接入网关-01');
    await page.fill('#srv-group-input', '生产环境');
    await page.fill('#srv-host-input', info.ssh_host);
    await page.fill('#srv-port-input', String(info.ssh_edge_port));
    await page.fill('#srv-user-input', info.ssh_user);
    await page.fill('#srv-password-input', info.ssh_pass);
    await page.fill(
      '#server-form-modal input[placeholder="nginx, k8s-master, hk-bgp"]',
      'nginx, tls1.3, gateway'
    );
    await page.fill(
      '#server-form-modal input[placeholder="例如 /data/www 或留空使用主目录"]',
      info.sftp_root
    );
    await page.click('#srv-save-submit-btn');
    await page.waitForSelector('#server-form-modal', { state: 'hidden', timeout: 15000 });

    // Add Server 2 (High-Stress PostgreSQL Node)
    await page.click('#add-server-btn');
    await page.waitForSelector('#server-form-modal', { state: 'visible' });
    await page.fill('#srv-name-input', '新加坡核心交易库-02');
    await page.fill('#srv-group-input', '核心数据库');
    await page.fill('#srv-host-input', info.ssh_host);
    await page.fill('#srv-port-input', String(info.ssh_db_port));
    await page.fill('#srv-user-input', info.ssh_user);
    await page.fill('#srv-password-input', info.ssh_pass);
    await page.fill(
      '#server-form-modal input[placeholder="nginx, k8s-master, hk-bgp"]',
      'postgresql, wal, nvme'
    );
    await page.fill(
      '#server-form-modal input[placeholder="例如 /data/www 或留空使用主目录"]',
      info.sftp_root
    );
    await page.click('#srv-save-submit-btn');
    await page.waitForSelector('#server-form-modal', { state: 'hidden', timeout: 15000 });
    await assertNoHorizontalOverflow(page, 'Servers-Populated-390');

    // =========================================================================
    // 3. Mobile Off-Canvas Drawer & Desktop 1440px Non-Regression (F-01)
    // =========================================================================
    console.log('[e2e] 3/8 Testing mobile navigation drawer & desktop non-regression...');
    await assertElementInViewport(page, '#mobile-topbar', 'MobileTopbar-390');
    const closedSidebarHidden = await page.$eval('#app-sidebar', (el) => {
      const st = window.getComputedStyle(el);
      const r = el.getBoundingClientRect();
      return st.visibility === 'hidden' || r.right <= 0;
    });
    assert.ok(closedSidebarHidden, 'Expected #app-sidebar to be off-screen when closed at 390px');

    await page.click('#mobile-menu-toggle-btn');
    await page.waitForSelector('#app-sidebar.mobile-open', { state: 'visible' });
    await assertElementInViewport(page, '#app-sidebar', 'OpenSidebar-390');

    // Escape closes drawer
    await page.keyboard.press('Escape');
    await page.waitForSelector('#app-sidebar.mobile-open', { state: 'hidden' });

    // Backdrop tap closes drawer
    await page.click('#mobile-menu-toggle-btn');
    await page.waitForSelector('#app-sidebar.mobile-open', { state: 'visible' });
    await page.click('.mobile-drawer-backdrop', { position: { x: 350, y: 300 } });
    await page.waitForSelector('#app-sidebar.mobile-open', { state: 'hidden' });

    // Desktop 1440x940 check
    await page.setViewportSize({ width: 1440, height: 940 });
    const topbarDisplayDesktop = await page.$eval('#mobile-topbar', (el) =>
      window.getComputedStyle(el).display
    );
    assert.equal(topbarDisplayDesktop, 'none', 'Expected #mobile-topbar hidden on desktop 1440px');
    const sidebarBoxDesktop = await page.locator('#app-sidebar').boundingBox();
    assert.ok(
      sidebarBoxDesktop && Math.abs(sidebarBoxDesktop.width - 234) <= 2,
      `Expected 234px desktop sidebar, got ${JSON.stringify(sidebarBoxDesktop)}`
    );
    await assertNoHorizontalOverflow(page, 'Servers-Desktop-1440');

    // Verify all buttons inside every .server-card stay strictly within card bounds across desktop & mobile widths
    for (const cardVp of [
      { name: 'desktop-1440', width: 1440, height: 940 },
      { name: 'desktop-1280', width: 1280, height: 800 },
      { name: 'desktop-1024', width: 1024, height: 768 },
      { name: 'mobile-390', width: 390, height: 844 },
      { name: 'mobile-320', width: 320, height: 568 },
    ]) {
      await page.setViewportSize({ width: cardVp.width, height: cardVp.height });
      const cardBtnViolations = await page.evaluate(() => {
        const bad = [];
        for (const card of document.querySelectorAll('.server-card')) {
          const cr = card.getBoundingClientRect();
          if (cr.width <= 0) continue;
          for (const btn of card.querySelectorAll('button')) {
            const br = btn.getBoundingClientRect();
            if (br.width <= 0) continue;
            if (br.left < cr.left - 0.5 || br.right > cr.right + 0.5) {
              bad.push({
                cardId: card.id,
                cardLeft: Math.round(cr.left * 10) / 10,
                cardRight: Math.round(cr.right * 10) / 10,
                btnText: btn.textContent?.trim(),
                btnLeft: Math.round(br.left * 10) / 10,
                btnRight: Math.round(br.right * 10) / 10,
              });
            }
          }
        }
        return bad;
      });
      assert.deepEqual(
        cardBtnViolations,
        [],
        `Expected all .server-card buttons strictly inside card bounds at ${cardVp.name}, got ${JSON.stringify(cardBtnViolations)}`
      );
    }

    // =========================================================================
    // 4. Keychain Modals, Snippets Modal & SFTP 2-Tier Readability (375px & 320px)
    // =========================================================================
    console.log('[e2e] 4/8 Testing Keychain modals, Snippets modal & SFTP readability (375px & 320px)...');
    await page.setViewportSize({ width: 375, height: 812 });
    await navigateSection(page, '#nav-keychain-btn');
    await page.waitForSelector('#keychain-manager-view', { state: 'visible' });
    await page.click('#open-keygen-btn');
    await page.waitForSelector('#keygen-modal', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'KeygenModal-375');
    await assertMobileInputsFontSizeAtLeast16(page, 'KeygenModal-375');
    await page.fill('#keygen-name-input', 'HK-Prod-Ed25519-Master');
    await page.click('#keygen-submit-btn');
    await page.waitForSelector('#keygen-modal', { state: 'hidden', timeout: 15000 });
    await assertNoHorizontalOverflow(page, 'Keychain-Populated-375');

    // Also verify Keychain import modal .code-textarea >= 16px on mobile
    await page.click('#open-add-cred-btn');
    await page.locator('.modal-panel button:has-text("SSH 私钥")').click();
    await page.waitForSelector('.modal-panel .code-textarea', { state: 'visible' });
    await assertMobileInputsFontSizeAtLeast16(page, 'KeychainImportModal-375');
    await assertNoHorizontalOverflow(page, 'KeychainImportModal-375');
    await page.locator('.modal-panel .modal-footer button:has-text("取消")').click();

    // Verify SnippetManager modal >= 16px & create a real snippet for Terminal quick-menu
    await navigateSection(page, '#nav-snippets-btn');
    await page.waitForSelector('#snippet-manager-view', { state: 'visible' });
    await page.locator('#snippet-manager-view button:has-text("新建指令")').click();
    await page.waitForSelector('.modal-panel textarea.textarea', { state: 'visible' });
    await assertMobileInputsFontSizeAtLeast16(page, 'SnippetModal-375');
    await assertNoHorizontalOverflow(page, 'SnippetModal-375');
    await page.locator('.modal-panel input.input').first().fill('Nginx 配置自检与热重载');
    await page.locator('.modal-panel textarea.textarea').fill('nginx -t && systemctl status nginx --no-pager');
    await page.locator('.modal-panel button[type="submit"]').click();
    await page.waitForTimeout(300);

    // Return to Servers and test Standalone SFTP Modal + 2-tier mobile readability on 375px & 320px
    await navigateSection(page, '#nav-servers-btn');
    await page.locator('.server-card').first().locator('button:has-text("SFTP")').click();
    await page.waitForSelector('.sftp-standalone-modal', { state: 'visible' });
    await page.waitForSelector('.sftp-name-cell:has-text("nginx.conf")', { timeout: 15000 });
    await assertNoHorizontalOverflow(page, 'StandaloneSFTP-375');
    await assertMobileInputsFontSizeAtLeast16(page, 'StandaloneSFTP-375');

    // Verify clean virtual /etc/nginx path (zero leaked temp path names!)
    const sftpPathVal = await page.$eval('.sftp-path-input', (el) => el.value);
    assert.equal(sftpPathVal, '/etc/nginx', `Expected clean /etc/nginx SFTP path, got ${sftpPathVal}`);
    assert.ok(!sftpPathVal.includes('sns-e2e'), 'SFTP path must never expose temporary host paths');

    // Verify long filename width >= 180px on 375x812 and >= 32x32 touch targets on action buttons
    const sftpRowMetrics375 = await page.evaluate(() => {
      const longEl = Array.from(document.querySelectorAll('.sftp-entry-name')).find((el) =>
        el.textContent?.includes('prod-gateway-tls-upstream-security-hardening.conf')
      );
      const nameRect = longEl ? longEl.getBoundingClientRect() : null;
      const actionBtns = Array.from(
        document.querySelectorAll('.sftp-file-row .sftp-actions-group button')
      )
        .filter((b) => b.getBoundingClientRect().width > 0)
        .map((b) => {
          const r = b.getBoundingClientRect();
          return { w: r.width, h: r.height };
        });
      return { nameWidth: nameRect ? nameRect.width : 0, actionBtns };
    });
    assert.ok(
      sftpRowMetrics375.nameWidth >= 180,
      `Expected .sftp-entry-name width >= 180px on 375px viewport, got ${sftpRowMetrics375.nameWidth}`
    );
    assert.ok(sftpRowMetrics375.actionBtns.length > 0, 'Expected visible SFTP action buttons');
    for (const btn of sftpRowMetrics375.actionBtns) {
      assert.ok(
        btn.w >= 32 && btn.h >= 32,
        `Expected SFTP action button >= 32x32px, got ${JSON.stringify(btn)}`
      );
    }

    // Also verify 320x568 SFTP readability & Rename dialog long-path wrapping
    await page.setViewportSize({ width: 320, height: 568 });
    await assertNoHorizontalOverflow(page, 'StandaloneSFTP-320');
    const longNameWidth320 = await page.evaluate(() => {
      const longEl = Array.from(document.querySelectorAll('.sftp-entry-name')).find((el) =>
        el.textContent?.includes('prod-gateway-tls-upstream-security-hardening.conf')
      );
      return longEl ? longEl.getBoundingClientRect().width : 0;
    });
    assert.ok(
      longNameWidth320 >= 140,
      `Expected .sftp-entry-name width >= 140px even on 320px viewport, got ${longNameWidth320}`
    );

    await page.setViewportSize({ width: 375, height: 812 });
    await page
      .locator('.sftp-file-row:has-text("prod-gateway-tls-upstream-security-hardening.conf") button[title="重命名"]')
      .click();
    await page.waitForSelector('.modal-panel form input.input', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'SFTPRenameModal-375');
    await assertMobileInputsFontSizeAtLeast16(page, 'SFTPRenameModal-375');
    await page.locator('.modal-panel form button:has-text("取消")').click();

    await page.click('.sftp-name-cell:has-text("nginx.conf")');
    await page.waitForSelector('.sftp-editor-textarea', { state: 'visible', timeout: 10000 });
    await assertNoHorizontalOverflow(page, 'SFTPEditorModal-375');
    await assertMobileInputsFontSizeAtLeast16(page, 'SFTPEditorModal-375');
    await page.locator('.modal-panel:has(.sftp-editor-textarea) .modal-footer button:has-text("取消")').click();
    await page.locator('.sftp-standalone-modal .sftp-close-btn').click();
    await page.waitForSelector('.sftp-standalone-modal', { state: 'hidden' });

    // =========================================================================
    // 5. Monitor Center KPI Grids, Stacked Alerts/Policy Cards & Edge Touch Scrubbing
    // =========================================================================
    console.log('[e2e] 5/8 Collecting live SSH telemetry & testing Monitor stacked tables + edge scrubbing...');
    await navigateSection(page, '#nav-monitor-btn');
    await page.waitForSelector('#monitor-center-view', { state: 'visible' });

    // Collect twice to populate multi-point time-series charts + firing alerts
    await page.click('#monitor-collect-all-btn');
    await page.waitForTimeout(1400);
    await page.click('#monitor-collect-all-btn');
    await page.waitForTimeout(1400);

    const kpiCols375 = await page.$eval('.mon-kpi-grid', (el) =>
      window.getComputedStyle(el).gridTemplateColumns.trim().split(/\s+/).length
    );
    assert.equal(kpiCols375, 2, `Expected 2-column .mon-kpi-grid at 375px, got ${kpiCols375}`);
    await assertNoHorizontalOverflow(page, 'Monitor-Overview-375');
    await assertMobileInputsFontSizeAtLeast16(page, 'Monitor-Overview-375');

    // Test Compact Fleet Table sticky first column & zero overflow on 375px
    await page.click('button[title="紧凑表格视图"]');
    await page.waitForSelector('.mon-compact-fleet-table', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'Monitor-CompactFleetTable-375');
    const stickyPos = await page.$eval('.mon-compact-fleet-table td:first-child', (el) =>
      window.getComputedStyle(el).position
    );
    assert.equal(stickyPos, 'sticky', 'Expected sticky first column on .mon-compact-fleet-table');
    await page.click('button[title="卡片矩阵视图"]');

    // Switch to Detail tab and test left-edge, center, and right-edge touch scrubbing on TimeSeriesChart
    await page.click('#mon-tab-detail');
    await page.waitForSelector('#monitor-detail-pane .mon-chart-svg', { state: 'visible', timeout: 15000 });
    await assertMobileInputsFontSizeAtLeast16(page, 'Monitor-Detail-375');

    const chartCols375 = await page.$eval('.mon-charts-grid', (el) =>
      window.getComputedStyle(el).gridTemplateColumns.trim().split(/\s+/).length
    );
    assert.equal(chartCols375, 1, `Expected 1-column .mon-charts-grid at 375px, got ${chartCols375}`);

    const firstChartSvg = page.locator('.mon-chart-svg').first();
    await firstChartSvg.scrollIntoViewIfNeeded();
    const svgBox = await firstChartSvg.boundingBox();
    assert.ok(svgBox, 'Expected .mon-chart-svg boundingBox');

    for (const [edgeName, xPos] of [
      ['LeftEdge', svgBox.x + 2],
      ['Center', svgBox.x + svgBox.width * 0.65],
      ['RightEdge', svgBox.x + svgBox.width - 2],
    ]) {
      await page.evaluate(
        ({ x, y }) => {
          const svg = document.querySelector('.mon-chart-svg');
          if (!svg) return;
          const touchObj = new Touch({
            identifier: 1,
            target: svg,
            clientX: x,
            clientY: y,
            pageX: x,
            pageY: y,
          });
          svg.dispatchEvent(
            new TouchEvent('touchstart', {
              bubbles: true,
              cancelable: true,
              touches: [touchObj],
              targetTouches: [touchObj],
              changedTouches: [touchObj],
            })
          );
        },
        { x: xPos, y: svgBox.y + svgBox.height * 0.5 }
      );
      await page.waitForSelector('.mon-chart-tooltip', { state: 'visible', timeout: 5000 });
      await assertElementInViewport(page, '.mon-chart-tooltip', `MonitorTooltip-${edgeName}-375`);
      const tipBox = await page.locator('.mon-chart-tooltip').first().boundingBox();
      assert.ok(
        tipBox && tipBox.x >= 4 && tipBox.x + tipBox.width <= 375 - 4,
        `Expected Monitor chart tooltip clamped inside [4, 371] on ${edgeName}, got ${JSON.stringify(tipBox)}`
      );
    }
    await assertNoHorizontalOverflow(page, 'Monitor-Detail-Charts-375');

    // Check Monitor detail sub-tabs, stacked Alerts cards, and stacked 18-rule Policy cards on 375px
    await page.click('#mon-detail-subtab-procs');
    await assertNoHorizontalOverflow(page, 'Monitor-Detail-ProcsPorts-375');
    await page.click('#mon-detail-subtab-security');
    await assertNoHorizontalOverflow(page, 'Monitor-Detail-Security-375');

    // Check Monitor Policy sub-tab on 375px
    await page.click('#mon-tab-policy');
    await page.waitForSelector('.mon-policy-table tbody tr', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'Monitor-Policy-375');
    await assertMobileInputsFontSizeAtLeast16(page, 'Monitor-Policy-375');
    const policyCardStyle = await page.$eval('.mon-policy-table tbody tr', (tr) => {
      const r = tr.getBoundingClientRect();
      const inp = document.querySelector('.mon-policy-table .mon-rule-input');
      const inpRect = inp ? inp.getBoundingClientRect() : null;
      return {
        display: window.getComputedStyle(tr).display,
        width: r.width,
        inpHeight: inpRect ? inpRect.height : 0,
      };
    });
    assert.equal(policyCardStyle.display, 'flex', 'Expected stacked flex card-row on .mon-policy-table at 375px');
    assert.ok(policyCardStyle.width <= 375.5, `Expected policy card width <= 375px, got ${policyCardStyle.width}`);
    assert.ok(policyCardStyle.inpHeight >= 38, `Expected .mon-rule-input height >= 38px, got ${policyCardStyle.inpHeight}`);

    // Navigate to dedicated Alert Center (#nav-alerts-btn) and verify mobile cards, remediation expansion & ack on 375px
    await navigateSection(page, '#nav-alerts-btn');
    await page.waitForSelector('#alert-center-view .al-card', { state: 'visible', timeout: 10000 });
    await assertNoHorizontalOverflow(page, 'AlertCenter-375');
    await assertMobileInputsFontSizeAtLeast16(page, 'AlertCenter-375');
    const alertCardStyle = await page.$eval('#alert-center-view .al-card', (card) => {
      const r = card.getBoundingClientRect();
      return {
        width: r.width,
        hasAdvicePreview: Boolean(card.querySelector('.al-advice-preview')),
      };
    });
    assert.ok(alertCardStyle.width <= 375.5 && alertCardStyle.hasAdvicePreview, 'Expected AlertCenter card with smart advice within 375px');

    // Expand first alert card to verify smart remediation commands fit within 375px
    await page.locator('#alert-center-view .al-card .al-expand-btn').first().click();
    await page.waitForSelector('#alert-center-view .al-remediation-panel', { state: 'visible', timeout: 5000 });
    await assertNoHorizontalOverflow(page, 'AlertCenter-Expanded-375');

    // Acknowledge a firing alert directly on the mobile card!
    const ackBtn = page.locator('#alert-center-view .al-card button:has-text("确认知晓")').first();
    if ((await ackBtn.count()) > 0) {
      await ackBtn.click();
      await page.waitForTimeout(300);
      await assertNoHorizontalOverflow(page, 'AlertCenter-AfterAck-375');
    }

    // Desktop 1440px Monitor grid check (6 KPI cols, 2 chart cols, table layout preserved)
    await page.setViewportSize({ width: 1440, height: 940 });
    const policyRowDisplay1440 = await page.$eval('.mon-policy-table tbody tr', (tr) =>
      window.getComputedStyle(tr).display
    );
    assert.equal(policyRowDisplay1440, 'table-row', 'Expected desktop table-row on .mon-policy-table at 1440px');
    await page.click('#mon-tab-overview');
    const kpiCols1440 = await page.$eval('.mon-kpi-grid', (el) =>
      window.getComputedStyle(el).gridTemplateColumns.trim().split(/\s+/).length
    );
    assert.equal(kpiCols1440, 6, `Expected 6-column .mon-kpi-grid at 1440px, got ${kpiCols1440}`);
    await page.click('#mon-tab-detail');
    await page.click('#mon-detail-subtab-metrics');
    const chartCols1440 = await page.$eval('.mon-charts-grid', (el) =>
      window.getComputedStyle(el).gridTemplateColumns.trim().split(/\s+/).length
    );
    assert.equal(chartCols1440, 2, `Expected 2-column .mon-charts-grid at 1440px, got ${chartCols1440}`);

    // =========================================================================
    // 6. Terminal Workspace, Hoisted Toolbar Popovers (375/320/844x390/1440), Keybar Suppression & Latch Reset
    // =========================================================================
    console.log('[e2e] 6/8 Testing SSHv2 PTY, hoisted toolbar popovers (375/320/844x390/1440), keybar & 0364 latch...');
    await page.setViewportSize({ width: 375, height: 812 });
    await navigateSection(page, '#nav-servers-btn');
    await page
      .locator('.server-card:has-text("香港边缘接入网关-01") button:has-text("SSH 终端")')
      .click();
    await page.waitForSelector('#terminal-workspace', { state: 'visible' });
    await page.waitForSelector('#mobile-terminal-keybar', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'Terminal-Connected-375');

    // Wait for real SSHv2 PTY handshake to complete
    await page.waitForFunction(
      () => document.querySelector('.xterm-rows')?.textContent?.includes('hk-edge-gw-01'),
      null,
      { timeout: 15000 }
    );

    // Verify hoisted #term-new-tab-btn and #term-quick-snippet-btn popovers + elementFromPoint hit-testing
    // across 375x812, 320x568, 844x390 landscape, and 1440x940 desktop!
    for (const [vpW, vpH] of [
      [375, 812],
      [320, 568],
      [844, 390],
      [1440, 940],
    ]) {
      await page.setViewportSize({ width: vpW, height: vpH });

      // Test New Tab popover: visible, unclipped (>60px tall), below trigger, elementFromPoint hits .nav-item!
      await page.click('#term-new-tab-btn');
      await page.waitForSelector('.term-dropdown-newtab', { state: 'visible' });
      const newTabBtnBox = await page.locator('#term-new-tab-btn').boundingBox();
      const newTabMenuBox = await page.locator('.term-dropdown-newtab').boundingBox();
      assert.ok(
        newTabMenuBox &&
          newTabBtnBox &&
          newTabMenuBox.height >= 60 &&
          newTabMenuBox.x >= 4 &&
          newTabMenuBox.x + newTabMenuBox.width <= vpW - 4 &&
          newTabMenuBox.y >= newTabBtnBox.y + newTabBtnBox.height - 2,
        `Expected unclipped .term-dropdown-newtab positioned below trigger at ${vpW}x${vpH}, got menu=${JSON.stringify(
          newTabMenuBox
        )} btn=${JSON.stringify(newTabBtnBox)}`
      );
      const hitMenuItem = await page.evaluate(() => {
        const item = document.querySelector('.term-dropdown-newtab .nav-item');
        if (!item) return false;
        const r = item.getBoundingClientRect();
        const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
        return Boolean(hit && item.contains(hit));
      });
      assert.equal(hitMenuItem, true, `Expected elementFromPoint to hit .term-dropdown-newtab .nav-item at ${vpW}x${vpH}`);
      await page.keyboard.press('Escape');
      await page.waitForSelector('.term-dropdown-newtab', { state: 'hidden' });

      // Outside click dismiss
      await page.click('#term-new-tab-btn');
      await page.waitForSelector('.term-dropdown-newtab', { state: 'visible' });
      await page.mouse.click(vpW - 12, vpH - 40);
      await page.waitForSelector('.term-dropdown-newtab', { state: 'hidden' });

      // Test Quick Snippet popover: visible, unclipped (>60px tall), below trigger (NOT covering Row 2!), Escape dismiss
      await page.click('#term-quick-snippet-btn');
      await page.waitForSelector('.term-dropdown-snippets', { state: 'visible' });
      const quickBtnBox = await page.locator('#term-quick-snippet-btn').boundingBox();
      const quickMenuBox = await page.locator('.term-dropdown-snippets').boundingBox();
      assert.ok(
        quickMenuBox &&
          quickBtnBox &&
          quickMenuBox.height >= 60 &&
          quickMenuBox.x >= 4 &&
          quickMenuBox.x + quickMenuBox.width <= vpW - 4 &&
          quickMenuBox.y >= quickBtnBox.y + quickBtnBox.height - 2,
        `Expected unclipped .term-dropdown-snippets positioned below #term-quick-snippet-btn at ${vpW}x${vpH}, got menu=${JSON.stringify(
          quickMenuBox
        )} btn=${JSON.stringify(quickBtnBox)}`
      );
      await page.keyboard.press('Escape');
      await page.waitForSelector('.term-dropdown-snippets', { state: 'hidden' });
    }

    // Verify terminal search input >= 16px on mobile
    await page.setViewportSize({ width: 390, height: 844 });
    await page.click('button[title="搜索终端内容"]');
    await page.waitForSelector('.term-search-input', { state: 'visible' });
    await assertMobileInputsFontSizeAtLeast16(page, 'TerminalSearch-390');
    await page.click('button[title="搜索终端内容"]');

    // Test exact CTRL -> ^C -> 'd' == 0364 sequence (proving non-modifier virtual key ^C clears sticky CTRL latch!)
    await fetch(`${info.control_url}?reset=1`, { method: 'POST' });
    const ctrlBtn = page.locator('#mobile-terminal-keybar [data-vkey="ctrl"]');
    await ctrlBtn.click();
    assert.equal(
      await ctrlBtn.evaluate((el) => el.classList.contains('active')),
      true,
      'Expected CTRL button to latch .active on tap'
    );
    await page.click('#mobile-terminal-keybar [data-vkey="ctrl-c"]');
    assert.equal(
      await ctrlBtn.evaluate((el) => el.classList.contains('active')),
      false,
      'Expected ^C non-modifier virtual key to immediately clear sticky CTRL latch'
    );
    await page.locator('.xterm-helper-textarea').focus();
    await page.keyboard.type('d');
    await page.waitForTimeout(350);
    const seq0364Stats = await (await fetch(info.control_url)).json();
    assert.equal(
      seq0364Stats.raw_hex,
      '0364',
      `Expected CTRL -> ^C -> 'd' to transmit exact hex '0364' (not Ctrl+D 0x04), got ${JSON.stringify(seq0364Stats)}`
    );

    // Reset PTY byte recorder and test sticky CTRL latch + typing 'c' + direct TAB virtual key
    await fetch(`${info.control_url}?reset=1`, { method: 'POST' });
    await ctrlBtn.click();
    const hasActiveBefore = await ctrlBtn.evaluate((el) => el.classList.contains('active'));
    assert.equal(hasActiveBefore, true, 'Expected CTRL button to latch .active on tap');

    await page.locator('.xterm-helper-textarea').focus();
    await page.keyboard.type('c');
    await page.waitForTimeout(350);

    const hasActiveAfter = await ctrlBtn.evaluate((el) => el.classList.contains('active'));
    assert.equal(hasActiveAfter, false, 'Expected CTRL sticky latch to clear after 1 character');

    // Also test direct TAB virtual key
    await page.click('#mobile-terminal-keybar [data-vkey="tab"]');
    await page.waitForTimeout(350);

    const ptyStats = await (await fetch(info.control_url)).json();
    assert.ok(
      ptyStats.ctrl_c_count >= 1,
      `Expected SSHv2 PTY server to receive Ctrl+C (0x03) via sticky CTRL latch, got ${JSON.stringify(ptyStats)}`
    );
    assert.ok(
      ptyStats.tab_count >= 1,
      `Expected SSHv2 PTY server to receive TAB (0x09) via virtual keybar, got ${JSON.stringify(ptyStats)}`
    );

    // Verify latching CTRL then opening SFTP overlay:
    // (a) hides #mobile-terminal-keybar while drawer is open, and (b) clears sticky CTRL latch!
    await ctrlBtn.click();
    assert.equal(
      await ctrlBtn.evaluate((el) => el.classList.contains('active')),
      true,
      'Expected CTRL latched before opening SFTP drawer'
    );
    await page.click('#term-toggle-sftp-btn');
    await page.waitForSelector('.terminal-side-drawer', { state: 'visible' });
    const keybarDisplayDuringSftp = await page.$eval('#mobile-terminal-keybar', (el) =>
      window.getComputedStyle(el).display
    );
    assert.equal(
      keybarDisplayDuringSftp,
      'none',
      'Expected #mobile-terminal-keybar hidden while SFTP full-width drawer is open'
    );
    const sftpDrawerBox = await page.locator('.terminal-side-drawer').boundingBox();
    assert.ok(
      sftpDrawerBox && Math.abs(sftpDrawerBox.width - 390) <= 2,
      `Expected full-width 390px mobile SFTP drawer, got ${JSON.stringify(sftpDrawerBox)}`
    );
    await assertNoHorizontalOverflow(page, 'Terminal-SFTP-Overlay-390');
    await page.click('#term-toggle-sftp-btn');
    await page.waitForSelector('.terminal-side-drawer', { state: 'hidden' });
    assert.equal(
      await ctrlBtn.evaluate((el) => el.classList.contains('active')),
      false,
      'Expected sticky CTRL latch cleared when opening/closing side drawer'
    );

    // Verify AI Copilot overlay opens full-width (390px), hides keybar, and .copilot-composer-input >= 16px
    await page.click('#term-toggle-copilot-btn');
    await page.waitForSelector('.terminal-side-drawer', { state: 'visible' });
    const keybarDisplayDuringCopilot = await page.$eval('#mobile-terminal-keybar', (el) =>
      window.getComputedStyle(el).display
    );
    assert.equal(
      keybarDisplayDuringCopilot,
      'none',
      'Expected #mobile-terminal-keybar hidden while AI Copilot drawer is open'
    );
    const copilotDrawerBox = await page.locator('.terminal-side-drawer').boundingBox();
    assert.ok(
      copilotDrawerBox && Math.abs(copilotDrawerBox.width - 390) <= 2,
      `Expected full-width 390px mobile AI Copilot drawer, got ${JSON.stringify(copilotDrawerBox)}`
    );
    const copilotPillH390 = await page.$eval('.copilot-mode-pill', (el) =>
      el.getBoundingClientRect().height
    );
    assert.ok(
      copilotPillH390 >= 28,
      `Expected mobile .copilot-mode-pill height >= 28px at 390px, got ${copilotPillH390}`
    );
    await assertNoHorizontalOverflow(page, 'Terminal-Copilot-Overlay-390');
    await assertMobileInputsFontSizeAtLeast16(page, 'Terminal-Copilot-Overlay-390');
    await page.click('#term-toggle-copilot-btn');
    await page.waitForSelector('.terminal-side-drawer', { state: 'hidden' });

    // Stress-test >=18 rapid SSH PTY window-change resizes to ensure harness drains chReqs without stalling
    for (let i = 0; i < 18; i++) {
      const w = i % 2 === 0 ? 360 + (i % 5) * 10 : 780 + (i % 4) * 20;
      const h = i % 2 === 0 ? 640 : 900;
      await page.setViewportSize({ width: w, height: h });
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await fetch(`${info.control_url}?reset=1`, { method: 'POST' });
    await page.locator('.xterm-helper-textarea').focus();
    await page.keyboard.type('z');
    await page.waitForTimeout(250);
    const postResizePty = await (await fetch(info.control_url)).json();
    assert.equal(
      postResizePty.raw_hex,
      '7a',
      `Expected live SSH PTY channel responsive after 18 viewport resizes, got ${JSON.stringify(postResizePty)}`
    );

    // Desktop 1440px check: virtual keybar hidden & compact 22px copilot mode pills preserved
    await page.setViewportSize({ width: 1440, height: 940 });
    const keybarDisplay1440 = await page.$eval('#mobile-terminal-keybar', (el) =>
      window.getComputedStyle(el).display
    );
    assert.equal(
      keybarDisplay1440,
      'none',
      'Expected #mobile-terminal-keybar hidden on desktop 1440px'
    );
    await page.click('#term-toggle-copilot-btn');
    await page.waitForSelector('.terminal-side-drawer', { state: 'visible' });
    const copilotPillH1440 = await page.$eval('.copilot-mode-pill', (el) =>
      el.getBoundingClientRect().height
    );
    assert.ok(
      Math.abs(copilotPillH1440 - 22) <= 1.5,
      `Expected compact 22px desktop .copilot-mode-pill at 1440px, got ${copilotPillH1440}`
    );
    await page.click('#term-toggle-copilot-btn');
    await page.waitForSelector('.terminal-side-drawer', { state: 'hidden' });

    // =========================================================================
    // 7. AI Ops Session Drawer Escape, Mode Hint, Unified Diff & ShellSnippetActionBar
    // =========================================================================
    console.log('[e2e] 7/8 Testing AI Ops Escape dismissal, Unified Diff & ShellSnippetActionBar...');
    await page.setViewportSize({ width: 390, height: 844 });
    await navigateSection(page, '#nav-ai-btn');
    await page.waitForSelector('#aiops-center-view', { state: 'visible' });

    // Configure mock OpenAI SSE gateway & verify >=16px inputs
    await page.click('#ai-tab-providers');
    await assertMobileInputsFontSizeAtLeast16(page, 'AIOps-Providers-390');
    await page.fill('input[placeholder*="生产 DeepSeek"]', '本地零知识测试网关');
    await page.fill('input[placeholder*="https://api.deepseek.com/v1"]', info.llm_base_url);
    await page.fill('input[placeholder*="deepseek-chat"]', 'sns-secops-pro');
    await page.fill('input[placeholder="sk-..."]', 'sk-e2e-local-key');
    await page.click('button:has-text("加密保存并设为激活")');
    await page.waitForTimeout(500);
    await assertNoHorizontalOverflow(page, 'AIOps-Providers-390');

    // Run real AI diagnosis producing HITL Unified Diff card
    await page.click('#ai-tab-diagnosis');
    await page.waitForSelector('#ai-mobile-sessions-btn', { state: 'visible' });
    await assertMobileInputsFontSizeAtLeast16(page, 'AIOps-Diagnosis-390');

    // Verify visible security mode hint without hover
    const modeHintVisible = await page.locator('.ai-mode-hint').isVisible();
    assert.equal(modeHintVisible, true, 'Expected visible .ai-mode-hint caption on touch devices');

    // Test mobile session slide-over drawer + Escape dismissal + close button
    await page.click('#ai-mobile-sessions-btn');
    await page.waitForSelector('#ai-session-rail.mobile-open', { state: 'visible' });
    await assertElementInViewport(page, '#ai-session-rail', 'AISessionRail-390');
    await page.keyboard.press('Escape');
    await page.waitForSelector('#ai-session-rail.mobile-open', { state: 'hidden' });

    await page.fill('#ai-center-prompt-input', '请审计香港边缘网关 SSH 安全配置并生成加固变更对比');
    await page.click('#ai-center-send-btn');
    await page.waitForSelector('.ai-approval-card .diff-viewer', {
      state: 'visible',
      timeout: 20000,
    });
    await assertNoHorizontalOverflow(page, 'AIOps-HITL-Diff-390');

    const diffHeaderText = await page.locator('.ai-approval-card').first().textContent();
    assert.ok(
      diffHeaderText?.includes('/etc/ssh/sshd_config') && !diffHeaderText?.includes('sns-e2e'),
      `Expected clean /etc/ssh/sshd_config path in HITL card, got: ${diffHeaderText}`
    );

    const diffScrollable = await page.$eval('.diff-viewer', (el) => ({
      scrollWidth: el.scrollWidth,
      clientWidth: el.clientWidth,
    }));
    assert.ok(
      diffScrollable.scrollWidth >= diffScrollable.clientWidth,
      'Expected .diff-viewer to contain wide diff lines within its own scrollable container'
    );

    // Approve HITL change so turn 2 renders ShellSnippetActionBar (.copilot-snippet-row) and verify mobile readability!
    await page.locator('.ai-approval-card button:has-text("批准")').first().click();
    await page.waitForSelector('.copilot-cmd-box.copilot-snippet-row', {
      state: 'visible',
      timeout: 15000,
    });
    const snippetBarMetrics = await page.$eval('.copilot-cmd-box.copilot-snippet-row', (box) => {
      const code = box.querySelector('.copilot-snippet-code');
      const btn = box.querySelector('.copilot-cmd-btn');
      return {
        whiteSpace: code ? window.getComputedStyle(code).whiteSpace : '',
        btnHeight: btn ? btn.getBoundingClientRect().height : 0,
      };
    });
    assert.notEqual(
      snippetBarMetrics.whiteSpace,
      'nowrap',
      'Expected .copilot-snippet-code to wrap multi-line on <=768px instead of single-line ellipsis'
    );
    assert.ok(
      snippetBarMetrics.btnHeight >= 32,
      `Expected .copilot-cmd-btn touch target height >= 32px on mobile, got ${snippetBarMetrics.btnHeight}`
    );
    await assertNoHorizontalOverflow(page, 'AIOps-SnippetActionBar-390');

    // =========================================================================
    // 8. Populated VaultSecurity Tables, C-1..C-5 / N-1 / N-2 / R2-1 Adversarial Checks & Full 8-Viewport Sweep
    // =========================================================================
    console.log('[e2e] 8/8 Testing VaultSecurity tables, C-1..C-5 + N-1/N-2/R2-1 adversarial bounds & 8 viewports sweep...');
    await page.setViewportSize({ width: 320, height: 568 });
    await navigateSection(page, '#nav-vault-btn');
    await page.waitForSelector('#vault-security-view', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'VaultSecurity-Populated-320');
    await assertMobileInputsFontSizeAtLeast16(page, 'VaultSecurity-Populated-320');

    // Verify KnownHosts / AuditLogs tables do NOT crush CJK headers into 1-char vertical columns
    const vaultTableMetrics = await page.evaluate(() => {
      const ths = Array.from(document.querySelectorAll('#vault-security-view .data-table th'));
      return ths.map((th) => ({
        text: th.textContent?.trim(),
        whiteSpace: window.getComputedStyle(th).whiteSpace,
        width: th.getBoundingClientRect().width,
      }));
    });
    assert.ok(vaultTableMetrics.length > 0, 'Expected populated KnownHosts/AuditLogs table headers');
    for (const th of vaultTableMetrics) {
      assert.equal(th.whiteSpace, 'nowrap', `Expected nowrap on VaultSecurity th "${th.text}"`);
      assert.ok(th.width >= 40, `Expected readable header width >= 40px for "${th.text}", got ${th.width}`);
    }

    // --- Adversarial Regression Suite (C-1, C-2, C-3, C-4, C-5) ---
    const longGroup60 = 'AP-EAST-CORE-BGP-HIGH-SECURITY-PRODUCTION-CLUSTER-GROUP-0060';
    const longEdgeName60 = 'PROD-HK-BGP-ANYCAST-ULTRA-LONG-EDGE-GATEWAY-NODE-60CHARS-001';
    const longIpv6Name60 = 'IPV6-UNBROKEN60CHARSNODENAMEABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
    const ipv6Host = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';
    const longProvider60 = 'PROVIDER-DEEPSEEK-PRIVATE-ZERO-KNOWLEDGE-GATEWAY-60CHARS-001';
    const longModelId = 'deepseek-r1-distill-qwen-72b-enterprise-secops';

    await page.setViewportSize({ width: 390, height: 844 });
    await navigateSection(page, '#nav-servers-btn');

    // Add reachable 60-char server in 60-char group
    await page.click('#add-server-btn');
    await page.waitForSelector('#server-form-modal', { state: 'visible' });
    await page.fill('#srv-name-input', longEdgeName60);
    await page.fill('#srv-group-input', longGroup60);
    await page.fill('#srv-host-input', info.ssh_host);
    await page.fill('#srv-port-input', String(info.ssh_edge_port));
    await page.fill('#srv-user-input', info.ssh_user);
    await page.fill('#srv-password-input', info.ssh_pass);
    await page.click('#srv-save-submit-btn');
    await page.waitForSelector('#server-form-modal', { state: 'hidden', timeout: 15000 });

    // Add unreachable IPv6 60-char server in 60-char group
    await page.click('#add-server-btn');
    await page.waitForSelector('#server-form-modal', { state: 'visible' });
    await page.fill('#srv-name-input', longIpv6Name60);
    await page.fill('#srv-group-input', longGroup60);
    await page.fill('#srv-host-input', ipv6Host);
    await page.fill('#srv-port-input', '22');
    await page.fill('#srv-user-input', info.ssh_user);
    await page.fill('#srv-password-input', info.ssh_pass);
    await page.click('#srv-save-submit-btn');
    await page.waitForSelector('#server-form-modal', { state: 'hidden', timeout: 15000 });

    // C-1: Verify MonitorCenter .mon-node-card with 60-char group at 320x568 & 1440x940
    await navigateSection(page, '#nav-monitor-btn');
    await page.click('#mon-tab-overview');
    await page.click('#monitor-collect-all-btn');
    await page.waitForTimeout(1600);

    await page.setViewportSize({ width: 320, height: 568 });
    await assertNoHorizontalOverflow(page, 'C1-Monitor-LongGroup-320');
    const c1Metrics320 = await page.evaluate((grp) => {
      const cards = Array.from(document.querySelectorAll('.mon-node-card')).filter((c) =>
        c.querySelector('.mon-node-head > .tag-chip')?.textContent?.includes(grp)
      );
      return cards.map((card) => {
        const gauge = card.querySelector('.mon-score-gauge')?.getBoundingClientRect();
        const name = card.querySelector('.mon-node-name')?.getBoundingClientRect();
        const sub = card.querySelector('.mon-node-sub')?.getBoundingClientRect();
        const chip = card.querySelector('.mon-node-head > .tag-chip')?.getBoundingClientRect();
        return {
          nameText: card.querySelector('.mon-node-name')?.textContent?.slice(0, 24) || '',
          nameWidth: name ? name.width : 0,
          subWidth: sub ? sub.width : 0,
          gaugeRight: gauge ? gauge.right : 0,
          chipLeft: chip ? chip.left : 0,
          chipRight: chip ? chip.right : 0,
          cardRight: card.getBoundingClientRect().right,
        };
      });
    }, longGroup60);
    assert.equal(c1Metrics320.length, 2, `Expected 2 long-group .mon-node-card entries, got ${c1Metrics320.length}`);
    for (const m of c1Metrics320) {
      assert.ok(
        m.nameWidth >= 100 && m.subWidth >= 100,
        `[C-1] Expected .mon-node-name & .mon-node-sub width >= 100px at 320x568, got ${JSON.stringify(m)}`
      );
      assert.ok(
        m.gaugeRight <= m.chipLeft && m.chipRight <= m.cardRight + 0.5,
        `[C-1] Expected group chip strictly right of HealthScoreGauge and inside card at 320x568, got ${JSON.stringify(m)}`
      );
    }

    // R2-1: Verify dedicated AlertCenter (#nav-alerts-btn) cards wrap unbroken IPv6 strings at 320x568
    await navigateSection(page, '#nav-alerts-btn');
    await page.waitForFunction(
      (host) => document.querySelector('#alert-center-view')?.textContent?.includes(host),
      ipv6Host,
      { timeout: 15000 }
    );
    await assertNoHorizontalOverflow(page, 'R2-1-AlertCenter-IPv6-320');
    const r2AlertRowMetrics320 = await page.evaluate((host) => {
      const cards = Array.from(document.querySelectorAll('#alert-center-view .al-card'));
      return cards.map((card) => ({
        hasIpv6: Boolean(card.textContent?.includes(host)),
        scrollWidth: card.scrollWidth,
        clientWidth: card.clientWidth,
      }));
    }, ipv6Host);
    assert.ok(
      r2AlertRowMetrics320.some((r) => r.hasIpv6),
      `[R2-1] Expected IPv6 offline alert card in #alert-center-view at 320x568, got ${JSON.stringify(r2AlertRowMetrics320)}`
    );
    for (const r of r2AlertRowMetrics320) {
      assert.ok(
        r.scrollWidth <= r.clientWidth + 2,
        `[R2-1] Expected #alert-center-view .al-card scrollWidth <= clientWidth + 2 at 320x568, got ${JSON.stringify(r)}`
      );
    }
    await navigateSection(page, '#nav-monitor-btn');
    await page.click('#mon-tab-overview');

    await page.setViewportSize({ width: 1440, height: 940 });
    const c1NameWidth1440 = await page.evaluate((grp) => {
      const card = Array.from(document.querySelectorAll('.mon-node-card')).find((c) =>
        c.querySelector('.mon-node-head > .tag-chip')?.textContent?.includes(grp)
      );
      return card?.querySelector('.mon-node-name')?.getBoundingClientRect().width || 0;
    }, longGroup60);
    assert.ok(
      c1NameWidth1440 >= 200,
      `[C-1] Expected .mon-node-name width >= 200px at 1440x940, got ${c1NameWidth1440}`
    );

    // C-2, N-1, N-2 & C-4: Verify 60-char AI provider chip/card, desktop/tablet subnav, landscape server chips & IPv6 Patrol anomalies
    await page.setViewportSize({ width: 390, height: 844 });
    await navigateSection(page, '#nav-ai-btn');
    await page.click('#ai-tab-providers');
    await page.fill('input[placeholder*="生产 DeepSeek"]', longProvider60);
    await page.fill('input[placeholder*="https://api.deepseek.com/v1"]', info.llm_base_url);
    await page.fill('input[placeholder*="deepseek-chat"]', longModelId);
    await page.fill('input[placeholder="sk-..."]', 'sk-e2e-60char-provider');
    await page.click('button:has-text("加密保存并设为激活")');
    await page.waitForTimeout(500);

    // N-1: Verify BOTH 1440x940 AND 1024x768 desktop viewports keep all 4 .ai-subnav tabs 100% visible & clickable with ellipsized active provider chip
    for (const n1Vp of [
      { width: 1440, height: 940, expectSingleRow: true },
      { width: 1024, height: 768, expectSingleRow: false },
    ]) {
      await page.setViewportSize({ width: n1Vp.width, height: n1Vp.height });
      await page.waitForTimeout(100);
      await assertNoHorizontalOverflow(page, `N1-AIOps-Subnav-${n1Vp.width}x${n1Vp.height}`);
      const n1Metrics = await page.evaluate(() => {
        const titleEl = document.querySelector('#aiops-center-view .page-header-title');
        const chipEl = document.querySelector('#aiops-center-view .page-header button.tag-chip.teal');
        const chipSpan = chipEl ? chipEl.querySelector('span') : null;
        const subnavEl = document.querySelector('#aiops-center-view .ai-subnav');
        const titleRect = titleEl ? titleEl.getBoundingClientRect() : null;
        const chipRect = chipEl ? chipEl.getBoundingClientRect() : null;
        const subnavRect = subnavEl ? subnavEl.getBoundingClientRect() : null;
        const spanStyle = chipSpan ? window.getComputedStyle(chipSpan) : null;
        const tabIds = ['#ai-tab-diagnosis', '#ai-tab-patrol', '#ai-tab-memory', '#ai-tab-providers'];
        const tabs = tabIds.map((id) => {
          const el = document.querySelector(id);
          const r = el ? el.getBoundingClientRect() : null;
          let hitOk = false;
          if (el && r && r.width > 0 && r.height > 0) {
            const cx = r.left + r.width / 2;
            const cy = r.top + r.height / 2;
            const hit = document.elementFromPoint(cx, cy);
            hitOk = Boolean(hit && (hit === el || el.contains(hit)));
          }
          return {
            id,
            left: r ? r.left : -1,
            right: r ? r.right : 9999,
            width: r ? r.width : 0,
            hitOk,
          };
        });
        return {
          titleTop: titleRect ? titleRect.top : 0,
          titleBottom: titleRect ? titleRect.bottom : 0,
          titleLeft: titleRect ? titleRect.left : 0,
          titleRight: titleRect ? titleRect.right : 0,
          chipLeft: chipRect ? chipRect.left : -1,
          chipRight: chipRect ? chipRect.right : 9999,
          spanOverflow: spanStyle ? spanStyle.overflow : '',
          spanTextOverflow: spanStyle ? spanStyle.textOverflow : '',
          spanScrollWidth: chipSpan ? chipSpan.scrollWidth : 0,
          spanClientWidth: chipSpan ? chipSpan.clientWidth : 0,
          subnavTop: subnavRect ? subnavRect.top : 0,
          subnavLeft: subnavRect ? subnavRect.left : 0,
          subnavRight: subnavRect ? subnavRect.right : 0,
          subnavScrollWidth: subnavEl ? subnavEl.scrollWidth : 9999,
          subnavClientWidth: subnavEl ? subnavEl.clientWidth : 0,
          tabs,
        };
      });
      assert.ok(
        n1Metrics.subnavScrollWidth <= n1Metrics.subnavClientWidth + 1,
        `[N-1] Expected .ai-subnav non-clipped (${n1Vp.width}x${n1Vp.height}), got ${JSON.stringify(n1Metrics)}`
      );
      for (const tab of n1Metrics.tabs) {
        assert.ok(
          tab.left >= n1Metrics.subnavLeft - 1 &&
            tab.right <= n1Metrics.subnavRight + 1 &&
            tab.hitOk,
          `[N-1] Expected ${tab.id} fully visible & center-clickable inside .ai-subnav at ${n1Vp.width}x${n1Vp.height}, got ${JSON.stringify(tab)} in ${JSON.stringify(n1Metrics)}`
        );
      }
      assert.ok(
        n1Metrics.chipLeft >= n1Metrics.titleLeft - 1 &&
          n1Metrics.chipRight <= n1Metrics.titleRight + 1 &&
          n1Metrics.spanOverflow === 'hidden' &&
          n1Metrics.spanTextOverflow === 'ellipsis' &&
          n1Metrics.spanScrollWidth > n1Metrics.spanClientWidth,
        `[N-1] Expected button.tag-chip.teal to ellipsize cleanly inside .page-header-title at ${n1Vp.width}x${n1Vp.height}, got ${JSON.stringify(n1Metrics)}`
      );
      if (n1Vp.expectSingleRow) {
        assert.ok(
          n1Metrics.titleRight <= n1Metrics.subnavLeft + 1 &&
            Math.abs(n1Metrics.titleTop - n1Metrics.subnavTop) < 40,
          `[N-1] Expected single-row .page-header at 1440x940, got ${JSON.stringify(n1Metrics)}`
        );
      } else {
        assert.ok(
          n1Metrics.subnavTop >= n1Metrics.titleBottom - 2,
          `[N-1] Expected .ai-subnav to wrap cleanly onto row 2 at 1024x768, got ${JSON.stringify(n1Metrics)}`
        );
      }
    }

    // N-2: Verify 844x390 landscape #ai-tab-diagnosis keeps .ai-server-chip ellipsized inside .ai-chat-main
    await page.setViewportSize({ width: 844, height: 390 });
    await page.click('#ai-tab-diagnosis');
    await page.waitForSelector('.ai-server-chip', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'N2-AIOps-Diagnosis-844x390');
    const n2Metrics844 = await page.evaluate(
      ({ edge60, ipv660 }) => {
        const main = document.querySelector('#aiops-center-view .ai-chat-main');
        const mainRect = main ? main.getBoundingClientRect() : null;
        const chips = Array.from(document.querySelectorAll('#aiops-center-view .ai-server-chip')).map(
          (chip) => {
            const cr = chip.getBoundingClientRect();
            const sp = chip.querySelector('span');
            const spStyle = sp ? window.getComputedStyle(sp) : null;
            const txt = sp?.textContent || '';
            return {
              isLong60: txt === edge60 || txt === ipv660,
              left: cr.left,
              right: cr.right,
              width: cr.width,
              spanOverflow: spStyle ? spStyle.overflow : '',
              spanTextOverflow: spStyle ? spStyle.textOverflow : '',
              spanScrollWidth: sp ? sp.scrollWidth : 0,
              spanClientWidth: sp ? sp.clientWidth : 0,
            };
          }
        );
        return {
          mainScrollWidth: main ? main.scrollWidth : 9999,
          mainClientWidth: main ? main.clientWidth : 0,
          mainRight: mainRect ? mainRect.right : 0,
          chips,
        };
      },
      { edge60: longEdgeName60, ipv660: longIpv6Name60 }
    );
    assert.ok(
      n2Metrics844.mainScrollWidth <= n2Metrics844.mainClientWidth + 1,
      `[N-2] Expected .ai-chat-main.scrollWidth <= clientWidth + 1 at 844x390, got ${JSON.stringify(n2Metrics844)}`
    );
    const n2LongChips = n2Metrics844.chips.filter((c) => c.isLong60);
    assert.equal(n2LongChips.length, 2, `[N-2] Expected 2 60-char .ai-server-chip items, got ${n2LongChips.length}`);
    for (const ch of n2Metrics844.chips) {
      assert.ok(
        ch.right <= n2Metrics844.mainRight + 0.5,
        `[N-2] Expected .ai-server-chip right <= .ai-chat-main right at 844x390, got ${JSON.stringify(ch)} vs mainRight=${n2Metrics844.mainRight}`
      );
    }
    for (const ch of n2LongChips) {
      assert.ok(
        ch.spanOverflow === 'hidden' &&
          ch.spanTextOverflow === 'ellipsis' &&
          ch.spanScrollWidth > ch.spanClientWidth,
        `[N-2] Expected 60-char .ai-server-chip inner <span> ellipsis at 844x390, got ${JSON.stringify(ch)}`
      );
    }
    await page.click('#ai-tab-providers');

    await page.setViewportSize({ width: 320, height: 568 });
    await assertNoHorizontalOverflow(page, 'C2-AIOps-Providers-320');
    const c2Metrics320 = await page.evaluate(() => {
      const chip = document.querySelector('#aiops-center-view .page-header button.tag-chip.teal');
      const pb = document.querySelector('#aiops-center-view .page-body');
      const cr = chip ? chip.getBoundingClientRect() : null;
      return {
        chipLeft: cr ? cr.left : -1,
        chipRight: cr ? cr.right : 9999,
        chipWidth: cr ? cr.width : 0,
        pbScrollWidth: pb ? pb.scrollWidth : 9999,
        pbClientWidth: pb ? pb.clientWidth : 0,
      };
    });
    assert.ok(
      c2Metrics320.chipLeft >= 8 && c2Metrics320.chipRight <= 320 && c2Metrics320.chipWidth >= 120,
      `[C-2] Expected active provider header chip clamped inside 320px viewport, got ${JSON.stringify(c2Metrics320)}`
    );
    assert.ok(
      c2Metrics320.pbScrollWidth <= 321,
      `[C-2] Expected #ai-tab-providers .page-body.scrollWidth <= 321 at 320x568, got ${JSON.stringify(c2Metrics320)}`
    );

    // Run Patrol to trigger unbroken [2001:0db8:...]:22 anomaly in f.anomalies (C-4)
    await page.click('#ai-tab-patrol');
    await page.click('#ai-run-patrol-now-btn');
    await page.waitForFunction(
      (host) => document.querySelector('.patrol-findings-grid')?.textContent?.includes(host),
      ipv6Host,
      { timeout: 20000 }
    );
    await assertNoHorizontalOverflow(page, 'C4-AIOps-Patrol-IPv6-320');
    const c4PatrolScrollW = await page.$eval('#aiops-center-view .page-body', (pb) => pb.scrollWidth);
    assert.ok(
      c4PatrolScrollW <= 321,
      `[C-4] Expected #ai-tab-patrol .page-body.scrollWidth <= 321 with IPv6 anomaly at 320x568, got ${c4PatrolScrollW}`
    );

    // C-3 & C-5: Verify IPv6 host + server name in .term-dropdown-newtab at 1440x940 & Frame-0 320x568
    await page.setViewportSize({ width: 1440, height: 940 });
    await navigateSection(page, '#nav-terminals-btn');
    // Open & close right-aligned quick-snippet menu at 1440x940 first to seed prior desktop coordinates
    await page.click('#term-quick-snippet-btn');
    await page.waitForSelector('.term-dropdown-snippets', { state: 'visible' });
    await page.keyboard.press('Escape');
    await page.waitForSelector('.term-dropdown-snippets', { state: 'hidden' });

    await page.click('#term-new-tab-btn');
    await page.waitForSelector('.term-dropdown-newtab', { state: 'visible' });
    const c3Metrics1440 = await page.evaluate((host) => {
      const menu = document.querySelector('.term-dropdown-newtab');
      const items = Array.from(document.querySelectorAll('.term-dropdown-newtab .nav-item'));
      const ipv6Item = items.find((el) => el.textContent?.includes(host));
      const spans = ipv6Item ? ipv6Item.querySelectorAll('span') : [];
      return {
        menuScrollWidth: menu ? menu.scrollWidth : 999,
        menuClientWidth: menu ? menu.clientWidth : 0,
        nameWidth: spans[0] ? spans[0].getBoundingClientRect().width : 0,
        hostWidth: spans[1] ? spans[1].getBoundingClientRect().width : 0,
      };
    }, ipv6Host);
    assert.ok(
      c3Metrics1440.nameWidth >= 95 &&
        c3Metrics1440.hostWidth >= 60 &&
        c3Metrics1440.menuScrollWidth <= c3Metrics1440.menuClientWidth + 1,
      `[C-3] Expected dual-visible IPv6 name & host without menu overflow at 1440x940, got ${JSON.stringify(c3Metrics1440)}`
    );
    await page.keyboard.press('Escape');
    await page.waitForSelector('.term-dropdown-newtab', { state: 'hidden' });

    // Resize 1440x940 -> 320x568 and capture Commit Frame 0 via MutationObserver (C-5) + IPv6 widths (C-3)
    await page.setViewportSize({ width: 320, height: 568 });
    await page.evaluate(() => {
      // @ts-ignore
      window.__dropdownCommitRects = [];
      const mo = new MutationObserver(() => {
        const menu = document.querySelector('.term-dropdown-newtab');
        if (menu) {
          const r = menu.getBoundingClientRect();
          // @ts-ignore
          window.__dropdownCommitRects.push({ left: r.left, right: r.right, width: r.width });
        }
      });
      mo.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['style'],
      });
      // @ts-ignore
      window.__dropdownMo = mo;
    });
    await page.click('#term-new-tab-btn');
    await page.waitForSelector('.term-dropdown-newtab', { state: 'visible' });
    const c3c5Metrics320 = await page.evaluate((host) => {
      // @ts-ignore
      window.__dropdownMo?.disconnect();
      // @ts-ignore
      const commits = window.__dropdownCommitRects || [];
      const menu = document.querySelector('.term-dropdown-newtab');
      const mr = menu ? menu.getBoundingClientRect() : null;
      const items = Array.from(document.querySelectorAll('.term-dropdown-newtab .nav-item'));
      const ipv6Item = items.find((el) => el.textContent?.includes(host));
      const spans = ipv6Item ? ipv6Item.querySelectorAll('span') : [];
      return {
        commitCount: commits.length,
        frame0Left: commits[0] ? commits[0].left : mr ? mr.left : -1,
        frame0Right: commits[0] ? commits[0].right : mr ? mr.right : 9999,
        allCommitsInBounds: commits.every((c) => c.left >= 4 && c.right <= 316),
        menuScrollWidth: menu ? menu.scrollWidth : 999,
        menuClientWidth: menu ? menu.clientWidth : 0,
        nameWidth: spans[0] ? spans[0].getBoundingClientRect().width : 0,
        hostWidth: spans[1] ? spans[1].getBoundingClientRect().width : 0,
      };
    }, ipv6Host);
    assert.ok(
      c3c5Metrics320.commitCount >= 1 &&
        c3c5Metrics320.frame0Left >= 4 &&
        c3c5Metrics320.frame0Right <= 316 &&
        c3c5Metrics320.allCommitsInBounds,
      `[C-5] Expected Commit Frame 0 (and all commits) of .term-dropdown-newtab inside 320px viewport, got ${JSON.stringify(c3c5Metrics320)}`
    );
    assert.ok(
      c3c5Metrics320.nameWidth >= 95 &&
        c3c5Metrics320.hostWidth >= 60 &&
        c3c5Metrics320.menuScrollWidth <= c3c5Metrics320.menuClientWidth + 1,
      `[C-3] Expected dual-visible IPv6 name & host without menu overflow at 320x568, got ${JSON.stringify(c3c5Metrics320)}`
    );
    await page.keyboard.press('Escape');
    await page.waitForSelector('.term-dropdown-newtab', { state: 'hidden' });

    // Sweep all 9 sections across all 8 viewports (including tablet-820 & landscape-844x390!) in BOTH dark and light themes!
    const sectionBtns = [
      ['servers', '#nav-servers-btn'],
      ['monitor', '#nav-monitor-btn'],
      ['alerts', '#nav-alerts-btn'],
      ['vulns', '#nav-vulns-btn'],
      ['terminals', '#nav-terminals-btn'],
      ['ai', '#nav-ai-btn'],
      ['approvals', '#nav-approvals-btn'],
      ['keychain', '#nav-keychain-btn'],
      ['snippets', '#nav-snippets-btn'],
      ['vault', '#nav-vault-btn'],
    ];

    for (const themeMode of ['dark', 'light']) {
      await page.evaluate((t) => {
        document.documentElement.setAttribute('data-theme', t);
      }, themeMode);

      for (const vp of VIEWPORTS) {
        await page.setViewportSize({ width: vp.width, height: vp.height });
        for (const [secName, btnSel] of sectionBtns) {
          await navigateSection(page, btnSel);
          await page.waitForTimeout(70);
          await assertNoHorizontalOverflow(page, `Sweep-${secName}-${vp.name}-${themeMode}`);

          if (secName === 'ai' && (vp.width === 320 || vp.name === 'landscape-844x390')) {
            for (const subTabId of [
              '#ai-tab-diagnosis',
              '#ai-tab-patrol',
              '#ai-tab-memory',
              '#ai-tab-providers',
            ]) {
              await page.click(subTabId);
              await page.waitForTimeout(40);
              await assertNoHorizontalOverflow(
                page,
                `Sweep-ai-${subTabId}-${vp.name}-${themeMode}`
              );
            }
          }
        }
      }
    }

    // Finally verify Screen Lock state at 320px
    await page.setViewportSize({ width: 320, height: 568 });
    await page.click('#mobile-lock-btn');
    await page.waitForSelector('#auth-gate-card', { state: 'visible' });
    await assertNoHorizontalOverflow(page, 'ScreenLocked-320');

    assert.deepEqual(
      cspViolations,
      [],
      `Expected zero CSP violations, got: ${JSON.stringify(cspViolations)}`
    );
    assert.deepEqual(
      runtimeErrors,
      [],
      `Expected zero browser runtime errors, got: ${JSON.stringify(runtimeErrors)}`
    );

    console.log('[e2e] PASS: All 8 viewports (320px..1440px incl. 1024x768, 820px & 844x390), Light & Dark themes, C-1..C-5 + N-1/N-2/R2-1 60-char/IPv6 bounds, hoisted popovers, >=16px inputs, 2-tier SFTP, stacked Monitor cards, edge scrubbing, SSHv2 PTY keybar/latch, AI HITL Diff + SnippetBar, and VaultSecurity tables passed with zero overflow and zero errors!');
  } finally {
    if (browser) {
      await browser.close();
    }
    await stop();
  }
}

runSuite().catch((err) => {
  console.error('[e2e] FAILED:', err);
  process.exit(1);
});
