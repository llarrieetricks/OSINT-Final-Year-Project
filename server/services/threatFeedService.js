
const axios = require("axios");

const URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/";
const REQUEST_TIMEOUT = 10000;

async function checkUrlhaus(url) {
  if (!url || typeof url !== "string") {
    throw new Error("A valid URL is required.");
  }

  const authKey = process.env.URLHAUS_AUTH_KEY;

  if (!authKey || authKey === "your_actual_auth_key") {
    return {
      source: "URLhaus",
      available: false,
      matched: null,
      queryStatus: "not_configured",
      error: "URLhaus API key is missing or not configured.",
    };
  }

  try {
    const payload = new URLSearchParams();
    payload.append("url", url);

    const response = await axios.post(
      URLHAUS_API,
      payload.toString(),
      {
        headers: {
          "Auth-Key": authKey,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout: REQUEST_TIMEOUT,
      }
    );

    const data = response.data;

    if (data.query_status === "no_results") {
      return {
        source: "URLhaus",
        available: true,
        matched: false,
        queryStatus: "no_results",
        url,
        checkedAt: new Date(),
      };
    }

    if (data.query_status === "ok") {
      return {
        source: "URLhaus",
        available: true,
        matched: true,
        queryStatus: "ok",
        url: data.url || url,
        urlhausId: data.id || null,
        urlStatus: data.url_status || null,
        threat: data.threat || null,
        tags: data.tags || [],
        dateAdded: data.date_added || null,
        reporter: data.reporter || null,
        reference: data.urlhaus_reference || null,
        payloads: data.payloads || [],
        checkedAt: new Date(),
      };
    }

    return {
      source: "URLhaus",
      available: false,
      matched: null,
      queryStatus: data.query_status || "unknown",
      error: "Unexpected URLhaus response.",
      checkedAt: new Date(),
    };
  } catch (error) {
    console.error(
      "URLhaus lookup failed:",
      error.response?.data || error.message
    );

    return {
      source: "URLhaus",
      available: false,
      matched: null,
      queryStatus: "error",
      error: error.response?.data?.query_status || error.message,
      checkedAt: new Date(),
    };
  }
}

module.exports = {
  checkUrlhaus,
};
