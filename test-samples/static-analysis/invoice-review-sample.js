const encodedCommand = "Y29uc29sZS5sb2coJ1N0YXRpYyBhbmFseXNpcyBKUyBzYW1wbGUnKTs=";

function decodeCommand() {
  return Buffer.from(encodedCommand, "base64").toString("utf8");
}

async function simulateCallback() {
  const target = "https://example.invalid/api/report";
  const payload = {
    sample: "static-analysis-js",
    now: new Date().toISOString(),
    platform: process.platform,
  };

  try {
    await fetch(target, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  } catch (error) {
    console.error("Expected callback failure for local test sample", error.message);
  }
}

(async () => {
  const command = decodeCommand();
  eval(command);
  await simulateCallback();
})();
