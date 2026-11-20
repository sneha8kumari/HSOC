const { chromium } = require('playwright');
const path = require('path');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  console.log('Navigating to http://localhost:5174...');
  await page.goto('http://localhost:5174', { waitUntil: 'load' });
  await page.waitForTimeout(2000);

  // Locate the Copilot chat input
  const input = page.getByPlaceholder('Ask a question about this incident...');
  await input.fill('hello');
  console.log('Filled input with "hello"');

  // Press Enter or click send button
  await input.press('Enter');
  console.log('Pressed Enter to submit');

  // Wait 4 seconds for streaming tokens to arrive
  await page.waitForTimeout(4000);

  const outPath = path.resolve(__dirname, 'phase5_copilot_hello.png');
  await page.screenshot({ path: outPath, fullPage: true });
  console.log('Saved phase 5 screenshot to:', outPath);

  await browser.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
