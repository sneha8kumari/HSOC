const { chromium } = require('playwright');
const path = require('path');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err.message));

  console.log('Navigating to http://localhost:5174...');
  await page.goto('http://localhost:5174', { waitUntil: 'load' });
  await page.waitForTimeout(2000);

  // Click 'Inspect telemetry log' button
  const inspectBtns = await page.$$('button');
  for (const btn of inspectBtns) {
    const text = await btn.textContent();
    if (text && text.includes('Inspect telemetry log')) {
      console.log('Clicking inspect button:', text);
      await btn.click();
      await page.waitForTimeout(400);
      break;
    }
  }

  const outPath = path.resolve(__dirname, 'phase4_component_redesign.png');
  await page.screenshot({ path: outPath, fullPage: true });
  console.log('Saved phase 4 screenshot to:', outPath);

  await browser.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
