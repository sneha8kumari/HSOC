const { chromium } = require("./node_modules/playwright");
const path = require("path");
const fs = require("fs");

async function capture() {
  console.log("Launching headless browser...");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  let url = "http://localhost:8000";
  console.log(`Navigating to ${url}...`);
  try {
    await page.goto(url, { timeout: 8000, waitUntil: "domcontentloaded" });
  } catch (err) {
    url = "http://localhost:5173";
    console.log(`Fallback to ${url}...`);
    await page.goto(url, { timeout: 8000, waitUntil: "domcontentloaded" });
  }

  // Wait for incidents or content to render
  await page.waitForTimeout(3000);

  // Look for incident item in sidebar
  const incidentCard = page.locator(".incident-card, [role='button']").first();
  if (await incidentCard.count() > 0) {
    console.log("Clicking on incident...");
    await incidentCard.click();
    await page.waitForTimeout(1500);
  }

  // Look for 'Approve step' button
  console.log("Locating 'Approve step' button...");
  const approveBtn = page.getByRole("button", { name: /Approve recommended remediation step|Approve step/i });
  if (await approveBtn.count() > 0) {
    console.log("Clicking 'Approve step'...");
    await approveBtn.first().click();
    // Wait for containment action response & status line
    await page.waitForTimeout(2000);
  } else {
    console.log("Approve button not found directly, checking text...");
    const textBtn = page.locator("button:has-text('Approve step')").first();
    if (await textBtn.count() > 0) {
      console.log("Clicking text-matched 'Approve step' button...");
      await textBtn.click();
      await page.waitForTimeout(2000);
    }
  }

  const outPath = path.resolve(__dirname, "soar_approved_action.png");
  await page.screenshot({ path: outPath, fullPage: true });
  console.log("Successfully captured screenshot at:", outPath);

  // Also copy to artifact directory
  const artifactDir = "C:\\Users\\Utkarsh Dubey\\.gemini\\antigravity\\brain\\125c8586-480a-44f1-beaf-4e7a51681dd4";
  if (fs.existsSync(artifactDir)) {
    const artPath = path.join(artifactDir, "soar_approved_action.png");
    fs.copyFileSync(outPath, artPath);
    console.log("Copied screenshot to artifact directory:", artPath);
  }

  await browser.close();
}

capture().catch((err) => {
  console.error("Screenshot capture error:", err);
  process.exit(1);
});
