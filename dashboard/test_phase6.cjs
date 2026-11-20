const { chromium } = require('playwright');
const path = require('path');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 950 } });
  const page = await context.newPage();

  console.log('Navigating to http://localhost:5174...');
  await page.goto('http://localhost:5174', { waitUntil: 'load' });
  await page.waitForTimeout(1500);

  // Click 'Attack forecasting' tab
  const forecastTab = page.getByRole('button', { name: 'Attack forecasting' });
  await forecastTab.click();
  await page.waitForTimeout(800);

  // Click 'Show the model\'s working' disclosure
  const disclosureBtn = page.getByRole('button', { name: "Show the model's working" });
  if (await disclosureBtn.isVisible()) {
    await disclosureBtn.click();
    await page.waitForTimeout(500);
  }

  const outPath = path.resolve(__dirname, 'phase6_markov_forecast.png');
  await page.screenshot({ path: outPath, fullPage: true });
  console.log('Saved phase 6 screenshot to:', outPath);

  await browser.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
