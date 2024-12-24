import { sendToLogQueue } from "../utils/log.js";

/**
 * Main Worker entry point:
 * - Exposes a single route `/fetchnvd`
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      if (url.pathname === "/fetchnvd") {
        // Only fetch a chunk of NVD data
        const result = await fetchNvdDataChunk(env);
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      } else {
        return new Response("Not Found", { status: 404 });
      }
    } catch (error) {
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

/**
 * Fetch only one chunk of NVD data in each invocation
 */
async function fetchNvdDataChunk(env) {
  const d1 = env.THREAT_INTEL_DB;
  const source = "nvd";
  const pageSize = 500; // process 500 CVEs per invocation
  
  // Retrieve last fetch metadata
  const metadata = await getFetchMetadata(d1, source);
  const {
    last_fetch_time = null,
    next_start_index = 0,
  } = metadata || {};

  // Determine date range - 30 days if no last fetch time
  const dataRetentionDays = 30;
  let lastModStartDate, lastModEndDate;
  if (last_fetch_time) {
    lastModStartDate = new Date(last_fetch_time).toISOString();
    lastModEndDate = new Date().toISOString();
  } else {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - dataRetentionDays);
    lastModStartDate = daysAgo.toISOString();
    lastModEndDate = new Date().toISOString();
  }

  // Construct request for a single chunk
  const requestURL =
    `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=${pageSize}` +
    `&startIndex=${next_start_index}` +
    `&lastModStartDate=${lastModStartDate}` +
    `&lastModEndDate=${lastModEndDate}`;

  let response;
  try {
    response = await fetch(requestURL, {
      headers: {
        Accept: "application/json",
        apiKey: env.NVD_API_KEY,
      },
    });
  } catch (e) {
    return { error: `NVD API request failed: ${e.message}`, nextIndex: next_start_index };
  }

  if (!response.ok) {
    const errorBody = await response.text();
    return { error: `NVD API error: ${errorBody}`, nextIndex: next_start_index };
  }

  const responseData = await response.json();
  const totalEntries = responseData.totalResults || 0;
  const vulnerabilities = responseData.vulnerabilities || [];

  // Convert each raw NVD item to your format
  const processedData = vulnerabilities.map(processVulnerabilityItem).filter(Boolean);

  // Store this chunk
  await storeVulnerabilitiesInD1(d1, processedData, env);
  
  // Update metadata
  const newStartIndex = next_start_index + (responseData.resultsPerPage || 0);
  const hasMore = newStartIndex < totalEntries;

  // If we still have data, store next_start_index in DB
  // Use the current run time as last fetch time
  const fetchTime = new Date().toISOString();
  await updateFetchMetadata(d1, source, fetchTime, newStartIndex);

  // Return info so logs or upstream triggers know whether to continue
  return {
    totalEntries,
    processedEntries: processedData.length,
    newStartIndex,
    hasMore,
    message: hasMore
      ? `Processed a chunk (size ${processedData.length}). More data remains.`
      : "All caught up with NVD data.",
  };
}

/**
 * Convert raw item to simplified format
 */
function processVulnerabilityItem(item) {
  if (!item?.cve?.id) return null;

  const cveData = item.cve;
  const metricsV31 = cveData.metrics?.cvssMetricV31?.[0]?.cvssData;
  const metricsV2 = cveData.metrics?.cvssMetricV2?.[0]?.cvssData;
  const metrics = metricsV31 || metricsV2 || {};

  const cleanedRefUrls = cveData.references
    ?.map((ref) => ref.url)
    .filter(Boolean)
    .join(",") || "";

  return {
    cveId: cveData.id,
    link: `https://nvd.nist.gov/vuln/detail/${cveData.id}`,
    description: cveData.descriptions?.find((d) => d.lang === "en")?.value || "",
    source: cveData.sourceIdentifier || "NVD",
    published: cveData.published || null,
    lastModified: cveData.lastModified || null,
    baseScore: metrics.baseScore || null,
    baseSeverity:
      metricsV31?.baseSeverity ||
      cveData.metrics?.cvssMetricV2?.[0]?.baseSeverity ||
      null,
    vectorString: metrics.vectorString || null,
    cwe: cveData.weaknesses?.[0]?.description?.[0]?.value || null,
    refUrls: cleanedRefUrls,
    fetched_at: new Date().toISOString(),
  };
}

/**
 * Store vulnerabilities in D1 in batches
 */
async function storeVulnerabilitiesInD1(d1, vulnerabilities, env) {
  const batchSize = 200; 
  if (!vulnerabilities?.length) return;

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

  for (let i = 0; i < vulnerabilities.length; i += batchSize) {
    const batch = vulnerabilities.slice(i, i + batchSize);
    for (const vuln of batch) {
      try {
        if (!vuln.cveId) continue;
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
      } catch (error) {
        // In production, you might collect or log these errors.
      }
    }
  }
}

/**
 * Fetch existing metadata from D1
 */
async function getFetchMetadata(d1, source) {
  const sql = `
    SELECT
      last_fetch_time,
      items_fetched,
      next_start_index
    FROM fetch_metadata
    WHERE source = ?
  `;
  try {
    return await d1.prepare(sql).bind(source).first();
  } catch (error) {
    return null;
  }
}

/**
 * Update metadata after fetching chunk
 */
async function updateFetchMetadata(d1, source, fetchTime, nextStartIndex) {
  const sql = `
    INSERT INTO fetch_metadata (
      source, last_fetch_time, next_start_index
    ) VALUES (?, ?, ?)
    ON CONFLICT(source) DO UPDATE SET
      last_fetch_time = excluded.last_fetch_time,
      next_start_index = excluded.next_start_index
  `;
  try {
    await d1.prepare(sql).bind(source, fetchTime, nextStartIndex).run();
  } catch (error) {
    // In production, handle or log errors
  }
}