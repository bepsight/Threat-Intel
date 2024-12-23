import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js";

/**
 * Main Worker entry point:
 * - Exposes a single route `/fetchnvd`
 * - Fetches data from NVD
 * - Stores it in D1 (vulnerabilities table) and FaunaDB
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/fetchnvd") {
        // Fetch NVD data
        await fetchNvdData(env);
        return new Response("NVD data fetched successfully.", { status: 200 });
      } else {
        // Not found
        await sendToLogQueue(env, {
          level: "warn",
          message: `[Worker] Route not found: ${url.pathname}`,
        });
        return new Response("Not Found", { status: 404 });
      }
    } catch (error) {
      // Log errors
      await sendToLogQueue(env, {
        level: "error",
        message: `Error in fetch handler: ${error.message}`,
        stack: error.stack,
      });
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

/**
 * Fetch data from NVD in pages, store incrementally in D1 and FaunaDB.
 */
async function fetchNvdData(env) {
  const d1 = env.THREAT_INTEL_DB; // D1 binding
  const fauna = new Client({ secret: env.FAUNA_SECRET }); // Fauna client

  // We'll track incremental fetching via `fetch_stats` table in D1
  const source = "nvd";

  let hasMoreData = true;
  let startIndex = 0;
  const pageSize = 2000;

  // Last fetch time from D1
  const lastFetchTime = await getLastFetchTime(d1, source, env);

  // Date range: either from last fetch time or X days ago
  const dataRetentionDays = 1;
  let lastModStartDate, lastModEndDate;
  if (lastFetchTime) {
    lastModStartDate = new Date(lastFetchTime).toISOString();
    lastModEndDate = new Date().toISOString();
  } else {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - dataRetentionDays);
    lastModStartDate = daysAgo.toISOString();
    lastModEndDate = new Date().toISOString();
  }

  // Keep fetching until no more data
  while (hasMoreData) {
    // Build NVD API URL
    const requestURL = 
      `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=${pageSize}`
      + `&startIndex=${startIndex}`
      + `&lastModStartDate=${lastModStartDate}`
      + `&lastModEndDate=${lastModEndDate}`;

    // Fetch from NVD
    let response;
    try {
      response = await fetch(requestURL, {
        headers: {
          "Accept": "application/json",
          "apiKey": env.NVD_API_KEY,
        },
      });
    } catch (e) {
      await sendToLogQueue(env, {
        level: "error",
        message: "NVD API request failed",
        data: { error: e.message, requestURL },
      });
      break; // stop or retry
    }

    // Check if response is OK
    if (!response.ok) {
      const errorBody = await response.text();
      await sendToLogQueue(env, {
        level: "error",
        message: "NVD API Error",
        data: { status: response.status, body: errorBody },
      });
      break;
    }

    const responseText = await response.text();
    const responseData = JSON.parse(responseText);

    // Log pagination details
    await sendToLogQueue(env, {
      level: "info",
      message: "NVD API Pagination Info",
      data: {
        totalResults: responseData.totalResults,
        resultsPerPage: responseData.resultsPerPage,
        startIndex,
        remainingItems: responseData.totalResults - startIndex,
      },
    });

    // If we have vulnerabilities, process them
    if (responseData?.vulnerabilities?.length > 0) {
      const processedData = [];

      // Process each vulnerability
      for (const item of responseData.vulnerabilities) {
        // Convert NVD item to a simpler structure
        const processedItem = processVulnerabilityItem(item);
        if (processedItem) {
          processedData.push(processedItem);
        }
      }

      // Store in D1
      await storeVulnerabilitiesInD1(d1, processedData, env);

      // Store in FaunaDB
      await storeVulnerabilitiesInFaunaDB(processedData, fauna, env);

      // Update pagination
      startIndex += responseData.resultsPerPage;
      hasMoreData = startIndex < responseData.totalResults;
    } else {
      // No vulnerabilities => done
      hasMoreData = false;
    }
  }

  // Update the last fetch time
  const fetchTime = new Date().toISOString();
  await updateLastFetchTime(d1, source, fetchTime, env);

  await sendToLogQueue(env, {
    level: "info",
    message: "Successfully fetched NVD data",
    data: {
      lastModStartDate,
      lastModEndDate,
      finalStartIndex: startIndex,
    },
  });
}

/**
 * Convert raw NVD JSON into a simpler object structure
 * suitable for D1 / FaunaDB.
 */
function processVulnerabilityItem(item) {
  if (!item?.cve?.id) {
    // Invalid item
    return null;
  }

  const cveData = item.cve;
  const firstMetric = cveData.metrics?.cvssMetricV31?.[0]?.cvssData || {};

  return {
    cveId: cveData.id,
    link: `https://nvd.nist.gov/vuln/detail/${cveData.id}`,
    description:
      cveData.descriptions?.find((d) => d.lang === "en")?.value || "",
    source: cveData.sourceIdentifier || "NVD",
    published: cveData.published || null,
    lastModified: cveData.lastModified || null,
    baseScore: firstMetric.baseScore || null,
    baseSeverity: firstMetric.baseSeverity || null,
    vectorString: firstMetric.vectorString || null,
    cwe: cveData.weaknesses?.[0]?.description?.[0]?.value || null,
    refUrls: JSON.stringify(cveData.references?.map((ref) => ref.url) || []),
    fetched_at: new Date().toISOString(),
  };
}

/**
 * Store NVD vulnerabilities in Cloudflare D1 database
 */
async function storeVulnerabilitiesInD1(d1, vulnerabilities, env) {
  try {
    if (!vulnerabilities?.length) {
      return;
    }

    const stmt = await d1.prepare(`
      INSERT INTO vulnerabilities (
        cve_id, description, source_identifier,
        published, last_modified, base_score,
        base_severity, vector_string, cwe,
        ref_urls, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(cve_id) DO UPDATE SET
        description = excluded.description,
        source_identifier = excluded.source_identifier,
        published = excluded.published,
        last_modified = excluded.last_modified,
        base_score = excluded.base_score,
        base_severity = excluded.base_severity,
        vector_string = excluded.vector_string,
        cwe = excluded.cwe,
        ref_urls = excluded.ref_urls
    `);

    for (const vuln of vulnerabilities) {
      if (!vuln.cveId) {
        continue; // Skip invalid
      }

      await stmt
        .bind(
          vuln.cveId,
          vuln.description,
          vuln.source,
          vuln.published,
          vuln.lastModified,
          vuln.baseScore,
          vuln.baseSeverity,
          vuln.vectorString,
          vuln.cwe,
          vuln.refUrls,
          vuln.fetched_at
        )
        .run();
    }

    await sendToLogQueue(env, {
      level: "info",
      message: `Stored ${vulnerabilities.length} vulnerabilities in D1 successfully`,
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: "error",
      message: `Error in storeVulnerabilitiesInD1: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Store vulnerabilities in FaunaDB
 */
async function storeVulnerabilitiesInFaunaDB(vulnerabilities, fauna, env) {
  try {
    if (!vulnerabilities?.length) {
      return;
    }

    for (const vuln of vulnerabilities) {
      if (!vuln.cveId) continue; // skip invalid

      const query = fql`
        let collectionExists = Collection.byName("Vulnerabilities").exists()
        if (!collectionExists) {
          Collection.create({ name: "Vulnerabilities" })
        }

        Vulnerabilities.create({ data: ${vuln} })
      `;
      await fauna.query(query);
    }

    await sendToLogQueue(env, {
      level: "info",
      message: `Stored ${vulnerabilities.length} vulnerabilities in FaunaDB successfully`,
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: "error",
      message: `Error storing vulnerabilities in FaunaDB: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

/**
 * Get last fetch time from D1
 */
async function getLastFetchTime(d1, source, env) {
  try {
    const result = await d1
      .prepare(`SELECT last_fetch_time FROM fetch_stats WHERE source = ?`)
      .bind(source)
      .first();
    return result?.last_fetch_time || null;
  } catch (error) {
    await sendToLogQueue(env, {
      level: "error",
      message: "Error fetching last fetch time",
      data: { error: error.message, stack: error.stack },
    });
    throw error;
  }
}

/**
 * Update last fetch time in D1
 */
async function updateLastFetchTime(d1, source, fetchTime, env) {
  try {
    await d1
      .prepare(
        `
        INSERT INTO fetch_stats (source, last_fetch_time, last_success_time, items_fetched)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
          last_fetch_time = excluded.last_fetch_time,
          last_success_time = excluded.last_success_time,
          items_fetched = fetch_stats.items_fetched + excluded.items_fetched
      `
      )
      .bind(source, fetchTime, fetchTime, 0)
      .run();

    await sendToLogQueue(env, {
      level: "info",
      message: "Updated fetch stats successfully",
      data: { source, fetchTime },
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: "error",
      message: "Failed to update fetch stats",
      data: { error: error.message, stack: error.stack },
    });
    throw error;
  }
}
