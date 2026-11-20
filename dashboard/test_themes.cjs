const { chromium } = require('playwright');
const path = require('path');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  let url = 'http://localhost:5174';
  try {
    await page.goto(url, { timeout: 4000, waitUntil: 'networkidle' });
  } catch (e) {
    url = 'http://localhost:5173';
    await page.goto(url, { timeout: 4000, waitUntil: 'networkidle' });
  }

  await page.waitForTimeout(1000);

  // 1. Click 'Attack forecasting' tab
  const forecastTab = await page.getByRole('button', { name: 'Attack forecasting' });
  if (await forecastTab.isVisible()) {
    await forecastTab.click();
    await page.waitForTimeout(600);
  }

  const darkPath = path.resolve(__dirname, 'phase3_dark_forecast.png');
  await page.screenshot({ path: darkPath, fullPage: true });
  console.log('Saved dark forecast screenshot:', darkPath);

  // 2. Click 'Light' theme toggle button in header
  const lightBtn = await page.getByRole('button', { name: 'Light' });
  if (await lightBtn.isVisible()) {
    await lightBtn.click();
    await page.waitForTimeout(500);
  }

  // 3. Click 'Investigation report' tab
  const reportTab = await page.getByRole('button', { name: 'Investigation report' });
  if (await reportTab.isVisible()) {
    await reportTab.click();
    await page.waitForTimeout(600);
  }

  const lightPath = path.resolve(__dirname, 'phase3_light_report.png');
  await page.screenshot({ path: lightPath, fullPage: true });
  console.log('Saved light report screenshot:', lightPath);

  await browser.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
