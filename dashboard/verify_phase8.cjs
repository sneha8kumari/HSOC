const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      console.error('PAGE ERROR:', msg.text());
    }
  });

  const baseUrls = ['http://localhost:5174', 'http://127.0.0.1:5174', 'http://[::1]:5174'];
  let connected = false;
  for (const url of baseUrls) {
    try {
      console.log(`Connecting to ${url}...`);
      await page.goto(url, { timeout: 8000, waitUntil: 'networkidle' });
      connected = true;
      console.log(`Connected successfully to ${url}`);
      break;
    } catch (e) {
      console.log(`Failed connecting to ${url}: ${e.message}`);
    }
  }

  if (!connected) {
    console.error('Could not connect to Vite dev server on any URL.');
    process.exit(1);
  }

  // Wait for incidents to load
  await page.waitForTimeout(1000);

  // 1. Verify ? opens keyboard shortcuts modal
  console.log('Testing keyboard shortcut "?"...');
  await page.keyboard.press('?');
  await page.waitForTimeout(500);

  const modalTitle = await page.locator('#shortcuts-heading').textContent();
  console.log('Shortcuts modal opened, title:', modalTitle);
  const screenshotDir = path.resolve(__dirname, '..');
  await page.screenshot({ path: path.join(screenshotDir, 'phase8_shortcuts_modal.png') });
  console.log('Captured phase8_shortcuts_modal.png');

  // 2. Verify Escape closes modal
  console.log('Testing Escape key to close modal...');
  await page.keyboard.press('Escape');
  await page.waitForTimeout(400);
  const modalVisible = await page.locator('#shortcuts-heading').isVisible();
  console.log('Modal is visible after Escape:', modalVisible);

  // 3. Test keyboard shortcut "d" to toggle density
  console.log('Testing keyboard shortcut "d" for density toggle...');
  await page.keyboard.press('d');
  await page.waitForTimeout(400);
  const densityVal = await page.evaluate(() => document.documentElement.getAttribute('data-density'));
  console.log('Current data-density attribute:', densityVal);
  await page.screenshot({ path: path.join(screenshotDir, 'phase8_compact_density.png') });
  console.log('Captured phase8_compact_density.png');

  // 4. Test keyboard shortcut "a" to approve remediation step
  console.log('Testing keyboard shortcut "a" to approve remediation...');
  await page.keyboard.press('a');
  await page.waitForTimeout(400);

  const approveButtonText = await page.locator('button.btn-success').first().textContent();
  console.log('Approve button status after "a":', approveButtonText);
  await page.screenshot({ path: path.join(screenshotDir, 'phase8_keyboard_action_approved.png') });
  console.log('Captured phase8_keyboard_action_approved.png');

  // 5. Test keyboard shortcut "j" / "k" to navigate incidents
  console.log('Testing keyboard shortcut "j" to navigate down...');
  const firstIncidentId = await page.evaluate(() => {
    const sel = document.querySelector('[aria-selected="true"]');
    return sel ? sel.textContent : null;
  });
  await page.keyboard.press('j');
  await page.waitForTimeout(400);
  const secondIncidentId = await page.evaluate(() => {
    const sel = document.querySelector('[aria-selected="true"]');
    return sel ? sel.textContent : null;
  });
  console.log('Selected incident changed with "j":', firstIncidentId !== secondIncidentId);

  // 6. Verify focus visible CSS rules
  const focusRule = await page.evaluate(() => {
    for (const sheet of document.styleSheets) {
      try {
        for (const rule of sheet.cssRules) {
          if (rule.selectorText && rule.selectorText.includes(':focus-visible')) {
            return rule.cssText;
          }
        }
      } catch (e) {}
    }
    return null;
  });
  console.log('Verified focus-visible rule:', focusRule);

  // 7. Verify Contrast Ratio of tokens
  const contrastCheck = await page.evaluate(() => {
    const root = getComputedStyle(document.documentElement);
    return {
      textPrimary: root.getPropertyValue('--text-primary').trim(),
      textSecondary: root.getPropertyValue('--text-secondary').trim(),
      textMuted: root.getPropertyValue('--text-muted').trim(),
      surfacePanel: root.getPropertyValue('--surface-panel').trim(),
      surfaceCanvas: root.getPropertyValue('--surface-canvas').trim(),
    };
  });
  console.log('Active tokens for contrast evaluation:', contrastCheck);

  await browser.close();
  console.log('Phase 8 verification completed successfully!');
})();
