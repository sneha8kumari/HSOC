const { chromium } = require('playwright');
const path = require('path');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 950 } });
  const page = await context.newPage();

  console.log('Navigating to http://localhost:5174...');
  await page.goto('http://localhost:5174', { waitUntil: 'load' });
  await page.waitForTimeout(1500);

  // 1. In Copilot chat, click the first case-specific question
  const questionBtn = page.getByRole('button', { name: /Why was this assigned a/ }).first();
  if (await questionBtn.isVisible()) {
    console.log('Clicking suggested question...');
    await questionBtn.click();
    // Wait 3.5 seconds for response to stream and render
    await page.waitForTimeout(3500);
  }

  const outChat = path.resolve(__dirname, 'phase7_copilot_briefing.png');
  await page.screenshot({ path: outChat, fullPage: true });
  console.log('Saved phase 7 briefing screenshot:', outChat);

  // 2. Click What-if simulation tab in Copilot panel
  const whatIfTab = page.getByRole('button', { name: 'What-if simulation' });
  if (await whatIfTab.isVisible()) {
    await whatIfTab.click();
    await page.waitForTimeout(400);

    // Click 'Run what-if projection' button
    const runBtn = page.getByRole('button', { name: 'Run what-if projection' });
    if (await runBtn.isVisible()) {
      await runBtn.click();
      await page.waitForTimeout(1000);
    }
  }

  const outWhatIf = path.resolve(__dirname, 'phase7_whatif_comparison.png');
  await page.screenshot({ path: outWhatIf, fullPage: true });
  console.log('Saved phase 7 what-if comparison screenshot:', outWhatIf);

  await browser.close();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
