const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  const screenshotDir = path.resolve(__dirname, '..');

  await page.goto('http://localhost:5174', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);

  // 1. Dark Mode full console
  await page.screenshot({ path: path.join(screenshotDir, 'delivery_final_dark.png') });
  console.log('Saved delivery_final_dark.png');

  // 2. Light Mode full console
  await page.click('button:has-text("Dark"), button:has-text("Light")');
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(screenshotDir, 'delivery_final_light.png') });
  console.log('Saved delivery_final_light.png');

  // 3. Markov tab view
  await page.click('button:has-text("Dark"), button:has-text("Light")'); // back to dark
  await page.waitForTimeout(300);
  await page.click('button:has-text("Attack forecasting")');
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(screenshotDir, 'delivery_markov_forecast.png') });
  console.log('Saved delivery_markov_forecast.png');

  await browser.close();
  console.log('Delivery captures complete!');
})();
