
const axios = require("axios");

const OPENPHISH_FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt";

const REQUEST_TIMEOUT = 10000;
const CACHE_DURATION = 10 * 60 * 1000;

let cachedFeed = null;
let lastFetchedAt = 0;

function normalizeFeedUrl(value) {
  try {
    const url = new URL(value.trim());

    if (!["http:", "https:"].includes(url.protocol)) {
      return null;
    }

    url.hash = "";

    return url.toString();
  } catch {
    return null;
  }
}

async function getOpenPhishFeed() {
  const now = Date.now();

  if (
    cachedFeed &&
    now - lastFetchedAt < CACHE_DURATION
  ) {
    return cachedFeed;
  }

  const response = await axios.get(OPENPHISH_FEED_URL, {
    timeout: REQUEST_TIMEOUT,
    responseType: "text",
  });

  if (typeof response.data !== "string") {
    throw new Error("Invalid OpenPhish feed response.");
  }

  const urls = response.data
    .split(/\r?\n/)
    .map(normalizeFeedUrl)
    .filter(Boolean);

  if (urls.length === 0) {
    throw new Error("OpenPhish feed contains no valid URLs.");
  }

  cachedFeed = new Set(urls);
  lastFetchedAt = now;

  return cachedFeed;
}

async function checkOpenPhish(inputUrl) {
  if (!inputUrl || typeof inputUrl !== "string") {
    throw new Error("A valid URL is required.");
  }

  const normalizedUrl = normalizeFeedUrl(inputUrl);

  if (!normalizedUrl) {
    throw new Error("A valid HTTP or HTTPS URL is required.");
  }

  try {
    const feed = await getOpenPhishFeed();

    const matched = feed.has(normalizedUrl);

    return {
      source: "OpenPhish",
      available: true,
      matched,
      queryStatus: matched ? "ok" : "no_results",
      url: normalizedUrl,
      feedEntries: feed.size,
      checkedAt: new Date(),
    };
  } catch (error) {
    console.error("OpenPhish lookup failed:", error.message);

    return {
      source: "OpenPhish",
      available: false,
      matched: null,
      queryStatus: "error",
      error: error.message,
      checkedAt: new Date(),
    };
  }
}

module.exports = {
  checkOpenPhish,
};
