const axios = require("axios");

const OSINT_SERVICE_URL = process.env.OSINT_SERVICE_URL || "http://localhost:5001";

async function getWhoisData(url) {
  const { data } = await axios.get(`${OSINT_SERVICE_URL}/whois`, {
    params: { url },
  });
  return data;
}

module.exports = { getWhoisData };
