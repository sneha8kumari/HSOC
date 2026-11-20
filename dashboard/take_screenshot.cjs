const { chromium } = require('playwright');
const path = require('path');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  // Try 5174 then 5173
  let url = 'http://localhost:5174';
  try {
    await page.goto(url, { timeout: 4000, waitUntil: 'networkidle' });
  } catch (e) {
    url = 'http://localhost:5173';
    await page.goto(url, { timeout: 4000, waitUntil: 'networkidle' });
  }

  // Wait 1 second for data to settle
  await page.waitForTimeout(1500);

  const outPath = path.resolve(__dirname, 'phase2_screenshot.png');
  await page.screenshot({ path: outPath, fullPage: true });
  console.log('Saved screenshot to:', outPath);
  await browser.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
