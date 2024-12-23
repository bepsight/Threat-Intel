import { sendToLogQueue } from "../utils/log.js";

/**
 * Main Worker entry point:
 * - Exposes a single route `/fetchnvd`
 * - Fetches data from NVD
 * - Stores it in D1 (vulnerabilities table)
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
 * Fetch data from NVD in pages, store incrementally in D1.
 */
async function fetchNvdData(env) {
  // We'll track incremental fetching via `fetch_stats` table in D1
  const d1 = env.THREAT_INTEL_DB; // D1 binding
  const source = "nvd";
  let hasMoreData = true;
  let startIndex = 0;
  const pageSize = 2000;

  const lastFetchTime = await getLastFetchTime(d1, source, env);

  // Date range logic
  const dataRetentionDays = 30;
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

  while (hasMoreData) {
    const requestURL =
      `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=${pageSize}` +
      `&startIndex=${startIndex}` +
      `&lastModStartDate=${lastModStartDate}` +
      `&lastModEndDate=${lastModEndDate}`;

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
      break;
    }

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

    if (responseData?.vulnerabilities?.length > 0) {
      const processedData = [];
      for (const item of responseData.vulnerabilities) {
        const processedItem = processVulnerabilityItem(item);
        if (processedItem) {
          processedData.push(processedItem);
        }
      }

      // Store in D1 only
      await storeVulnerabilitiesInD1(d1, processedData, env);

      startIndex += responseData.resultsPerPage;
      hasMoreData = startIndex < responseData.totalResults;
    } else {
      hasMoreData = false;
    }
  }

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
 * suitable for D1.
 */
function processVulnerabilityItem(item) {
  if (!item?.cve?.id) {
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
