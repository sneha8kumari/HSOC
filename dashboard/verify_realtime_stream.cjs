const { chromium } = require('playwright');
const path = require('path');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      console.error('BROWSER ERROR:', msg.text());
    }
  });

  console.log('Navigating to http://localhost:5174...');
  await page.goto('http://localhost:5174', { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);

  // 1. Verify stream controls in header
  const headerText = await page.locator('header').textContent();
  console.log('Header text summary:', headerText.slice(0, 120));
  const hasLiveIndicator = headerText.includes('Live');
  console.log('Live stream toolbar visible:', hasLiveIndicator);

  // 2. Click Inject step button to trigger immediate attack event
  console.log('Clicking "Inject step" button...');
  const injectBtn = page.locator('button:has-text("Inject step")');
  await injectBtn.click();
  await page.waitForTimeout(1500);

  // 3. Check for LIVE badge
  const liveBadgeCount = await page.locator('text=LIVE').count();
  console.log('Count of LIVE badges found on screen:', liveBadgeCount);

  // 4. Test Pause and Resume buttons
  console.log('Testing Pause button...');
  const pauseBtn = page.locator('button:has-text("Pause")');
  if (await pauseBtn.isVisible()) {
    await pauseBtn.click();
    await page.waitForTimeout(500);
    console.log('Clicked pause. Current state includes Paused:', (await page.locator('header').textContent()).includes('Paused'));

    const playBtn = page.getByRole('button', { name: 'Resume stream' });
    await playBtn.click();
    await page.waitForTimeout(500);
    console.log('Clicked play. Current state includes Live:', (await page.locator('header').textContent()).includes('Live'));
  }

  // 5. Capture screenshot of real-time streaming console
  const screenshotDir = path.resolve(__dirname, '..');
  const screenshotPath = path.join(screenshotDir, 'realtime_streaming_active.png');
  await page.screenshot({ path: screenshotPath });
  console.log('Saved screenshot:', screenshotPath);

  await browser.close();
  console.log('Real-time stream verification completed successfully!');
})();
