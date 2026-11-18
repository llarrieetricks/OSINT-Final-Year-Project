
const axios = require("axios");

const OSINT_SERVICE_URL =
  process.env.OSINT_SERVICE_URL || "http://localhost:5001";

const REQUEST_TIMEOUT = 10000;

async function getWhoisData(url) {
  const { data } = await axios.get(`${OSINT_SERVICE_URL}/whois`, {
    params: { url },
    timeout: REQUEST_TIMEOUT,
  });

  return data;
}

async function getSslData(url) {
  const { data } = await axios.get(`${OSINT_SERVICE_URL}/ssl`, {
    params: { url },
    timeout: REQUEST_TIMEOUT,
  });

  return data;
}

module.exports = {
  getWhoisData,
  getSslData,
};
