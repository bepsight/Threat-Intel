import { sendToLogQueue } from "../utils/log.js";

/**
 * Main Worker entry point:
 * - Exposes a single route `/fetchnvd`
 */
export default {
  async fetch(request, env) {
    console.log('[Worker] Starting worker execution');
    const url = new URL(request.url);

    try {
      if (url.pathname === "/fetchnvd") {
        console.log('[Worker] Handling /fetchnvd route');
        const result = await fetchNvdDataChunk(env);
        return new Response(JSON.stringify(result), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      } else {
        console.log(`[Worker] Route not found: ${url.pathname}`);
        return new Response("Not Found", { status: 404 });
      }
    } catch (error) {
      console.error('[Worker] Error in fetch handler:', error);
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

/**
 * Fetch only one chunk of NVD data in each invocation
 */
async function fetchNvdDataChunk(env) {
  console.log('[NVD] Starting to fetch NVD data chunk');
  const d1 = env.THREAT_INTEL_DB;
  const source = "nvd";
  const pageSize = 500; // process 500 CVEs per invocation
  
  // Retrieve last fetch metadata
  console.log('[NVD] Retrieving fetch metadata');
  const metadata = await getFetchMetadata(d1, source);
  console.log('[NVD] Current metadata:', metadata);
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

  console.log(`[NVD] Fetching data from ${lastModStartDate} to ${lastModEndDate}`);
  console.log(`[NVD] Starting from index: ${next_start_index}`);

  // Construct request for a single chunk
  const requestURL =
    `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=${pageSize}` +
    `&startIndex=${next_start_index}` +
    `&lastModStartDate=${lastModStartDate}` +
    `&lastModEndDate=${lastModEndDate}`;
  console.log('[NVD] Request URL:', requestURL);

  let response;
  try {
    console.log('[NVD] Sending request to NVD API');
    response = await fetch(requestURL, {
      headers: {
        Accept: "application/json",
        apiKey: env.NVD_API_KEY,
      },
    });
  } catch (e) {
    console.error('[NVD] API request failed:', e);
    return { error: `NVD API request failed: ${e.message}`, nextIndex: next_start_index };
  }

  if (!response.ok) {
    const errorBody = await response.text();
    console.error('[NVD] API error response:', errorBody);
    return { error: `NVD API error: ${errorBody}`, nextIndex: next_start_index };
  }

  const responseData = await response.json();
  const totalEntries = responseData.totalResults || 0;
  console.log(`[NVD] Total entries to process: ${totalEntries}`);
  const vulnerabilities = responseData.vulnerabilities || [];
  console.log(`[NVD] Retrieved ${vulnerabilities.length} vulnerabilities in this chunk`);

  // Convert each raw NVD item to your format
  const processedData = vulnerabilities.map(processVulnerabilityItem).filter(Boolean);
  console.log(`[NVD] Successfully processed ${processedData.length} vulnerabilities`);

  // Store this chunk
  console.log('[NVD] Storing vulnerabilities in D1');
  await storeVulnerabilitiesInD1(d1, processedData, env);
  
  // Update metadata
  const newStartIndex = next_start_index + (responseData.resultsPerPage || 0);
  const hasMore = newStartIndex < totalEntries;

  console.log(`[NVD] Progress: ${newStartIndex}/${totalEntries} (${((newStartIndex/totalEntries)*100).toFixed(2)}%)`);

  // If we still have data, store next_start_index in DB
  // Use the current run time as last fetch time
  const fetchTime = new Date().toISOString();
  console.log('[NVD] Updating fetch metadata');
  await updateFetchMetadata(d1, source, fetchTime, newStartIndex);

  // Return info so logs or upstream triggers know whether to continue
  const result = {
    totalEntries,
    processedEntries: processedData.length,
    newStartIndex,
    hasMore,
    message: hasMore
      ? `Processed a chunk (size ${processedData.length}). More data remains.`
      : "All caught up with NVD data.",
  };

  console.log('[NVD] Chunk processing complete:', result);
  return result;
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
  console.log(`[D1] Starting to store ${vulnerabilities.length} vulnerabilities`);
  const batchSize = 200; 
  if (!vulnerabilities?.length) {
    console.log('[D1] No vulnerabilities to store');
    return;
  }

  let successCount = 0;
  let errorCount = 0;

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
    console.log(`[D1] Processing batch ${Math.floor(i/batchSize) + 1}/${Math.ceil(vulnerabilities.length/batchSize)}`);
    for (const vuln of batch) {
      try {
        if (!vuln.cveId) continue;
        console.log(`[D1] Processing vulnerability: ${vuln.cveId}`);
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
        successCount++;
      } catch (error) {
        console.error(`[D1] Error processing ${vuln.cveId}:`, error);
        errorCount++;
      }
    }
  }

  console.log(`[D1] Storage complete - Success: ${successCount}, Errors: ${errorCount}`);
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