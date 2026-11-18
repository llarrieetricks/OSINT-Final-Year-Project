
const dns = require("node:dns");

const DNS_TIMEOUT = 5000;
const DNS_TRIES = 1;
const DNS_SERVERS = ["1.1.1.1", "8.8.8.8"];

async function resolveRecord(hostname, method) {
  const resolver = new dns.promises.Resolver();

  resolver.setServers(DNS_SERVERS);

  const lookup = resolver[method](hostname);

  let timeout;

  try {
    const records = await Promise.race([
      lookup,
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          resolver.cancel();
          reject(new Error("DNS_TIMEOUT"));
        }, DNS_TIMEOUT);
      }),
    ]);

    return {
      records,
      error: null,
    };
  } catch (error) {
    if (error.code === "ENODATA") {
      return {
        records: [],
        error: null,
      };
    }

    return {
      records: [],
      error: error.code || error.message,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function getDnsData(hostname) {
  if (!hostname || typeof hostname !== "string") {
    throw new Error("A valid hostname is required.");
  }

  const domain = hostname.trim().toLowerCase().replace(/\.$/, "");

  if (!domain || domain.length > 253 || /\s/.test(domain)) {
    throw new Error("A valid hostname is required.");
  }

  const methods = {
    A: "resolve4",
    AAAA: "resolve6",
    MX: "resolveMx",
    NS: "resolveNs",
    TXT: "resolveTxt",
    CNAME: "resolveCname",
  };

  const results = await Promise.all(
    Object.entries(methods).map(async ([type, method]) => {
      const result = await resolveRecord(domain, method);

      return [
        type,
        {
          records: result.records,
          error: result.error,
        },
      ];
    })
  );

  return {
    hostname: domain,
    records: Object.fromEntries(results),
    collectedAt: new Date(),
  };
}

module.exports = {
  getDnsData,
};
