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
  const startTime = Date.now();
  const d1 = env.THREAT_INTEL_DB;
  const source = "nvd";
  const pageSize = 1000; // process 500 CVEs per invocation
  
  // Retrieve last fetch metadata
  console.log('[NVD] Retrieving fetch metadata');
  const metadata = await getFetchMetadata(d1, source);
  console.log('[NVD] Current metadata:', metadata);
  const {
    next_start_index = 0,
  } = metadata || {};

  // Always fetch the last 30 days, rather than using last_fetch_time.
  const dataRetentionDays = 30;
  const daysAgo = new Date();
  daysAgo.setDate(daysAgo.getDate() - dataRetentionDays);
  const lastModStartDate = daysAgo.toISOString();
  const lastModEndDate = new Date().toISOString();

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

  // Add this before creating result object
  const existingCount = await d1.prepare(`
    SELECT COUNT(*) as count 
    FROM vulnerabilities 
    WHERE created_at >= ?
  `).bind(lastModStartDate).first();

  const result = {
    totalEntries,
    processedEntries: processedData.length,
    newStartIndex,
    hasMore,
    progress: {
      existingInDb: existingCount?.count || 0,
      remainingToFetch: totalEntries - newStartIndex,
      percentComplete: ((existingCount?.count / totalEntries) * 100).toFixed(2),
      dateRange: {
        from: lastModStartDate,
        to: lastModEndDate,
        retentionDays: dataRetentionDays
      }
    },
    message: hasMore
      ? `Processed ${processedData.length} entries. Remaining to fetch: ${totalEntries - newStartIndex} (${((newStartIndex/totalEntries)*100).toFixed(2)}% complete)`
      : `All caught up with NVD data. Total entries in DB: ${existingCount?.count}`,
    // Calculate and add total execution time
    totalExecutionTime: (() => {
      const totalMs = Date.now() - startTime;
      const totalMinutes = Math.floor(totalMs / 60000);
      const totalSeconds = Math.floor((totalMs % 60000) / 1000);
      return `${totalMinutes}m ${totalSeconds}s`;
    })()
  };

  console.log('[NVD] Progress Summary:', {
    totalVulnerabilities: totalEntries,
    existingInDb: existingCount?.count || 0,
    remainingToFetch: totalEntries - newStartIndex,
    percentComplete: ((existingCount?.count / totalEntries) * 100).toFixed(2) + '%'
  });

  console.log('[NVD] Chunk processing complete:', result);
  console.log(`[NVD] Total Execution Time: ${result.totalExecutionTime}`);

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
  console.log(`[D1] Starting batch insert of ${vulnerabilities.length} vulnerabilities`);

  let successCount = 0;
  let errorCount = 0;
  let errorDetails = [];
  const batchSize = 200;
  if (!vulnerabilities?.length) {
    console.log('[D1] No vulnerabilities to store');
    return;
  }

  // Log insertion progress in multiples of 10%
  let totalInserted = 0;
  let nextLogPercent = 0; // Start from 0%
  const totalVulns = vulnerabilities.length;
  console.log(`[D1] Insert progress: 0% done`);

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
    console.log(`[D1] Processing batch ${Math.floor(i/batchSize) + 1}/${Math.ceil(totalVulns/batchSize)}`);

    for (const vuln of batch) {
      try {
        if (!vuln.cveId) {
          console.log('[D1] Skipping vulnerability with no CVE ID');
          continue;
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
        successCount++;
      } catch (error) {
        errorCount++;
        errorDetails.push({
          cveId: vuln.cveId,
          error: error.message,
          code: error.code
        });
        console.error('[D1] Error inserting vulnerability:', {
          cveId: vuln.cveId,
          error: error.message,
          code: error.code,
          sql: stmt.toString(),
          stack: error.stack
        });
      }

      totalInserted++;
      const currentPercent = Math.floor((totalInserted / totalVulns) * 100);
      if (currentPercent >= nextLogPercent && nextLogPercent <= 100) {
        console.log(`[D1] Insert progress: ${currentPercent}% done`);
        nextLogPercent += 10;
      }
    }
  }
  console.log('[D1] Storage operation complete:', {
    totalProcessed: totalVulns,
    successful: successCount,
    failed: errorCount,
    errorDetails: errorDetails.length > 0 ? errorDetails : undefined
  });

  // Update fetch_metadata with results
  await updateFetchMetadata(d1, 'nvd', new Date().toISOString(), successCount);
}

/**
 * Fetch existing metadata from D1
 */
async function getFetchMetadata(d1, source) {
  console.log('[D1] Fetching metadata for source:', source);
  
  const sql = `
    SELECT
      last_fetch_time,
      last_success_time,
      items_fetched,
      next_start_index
    FROM fetch_metadata
    WHERE source = ?
  `;

  try {
    const startTime = Date.now();
    const result = await d1.prepare(sql).bind(source).first();
    
    console.log('[D1] Successfully retrieved fetch metadata:', {
      duration: `${Date.now() - startTime}ms`,
      result
    });
    return result;
  } catch (error) {
    console.error('[D1] Failed to get fetch metadata:', {
      error: error.message,
      sql: sql,
      source: source,
      code: error.code,
      stack: error.stack
    });
    return null;
  }
}

/**
 * Update metadata after fetching chunk
 */
async function updateFetchMetadata(d1, source, fetchTime, nextStartIndex) {
  console.log('[D1] Updating fetch metadata:', {
    source,
    fetchTime,
    nextStartIndex
  });

  const sql = `
    INSERT INTO fetch_metadata (
      source, last_fetch_time, last_success_time, items_fetched, next_start_index
    ) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(source) DO UPDATE SET
      last_fetch_time = excluded.last_fetch_time,
      last_success_time = CASE 
        WHEN excluded.items_fetched > 0 THEN excluded.last_fetch_time 
        ELSE fetch_metadata.last_success_time 
      END,
      items_fetched = fetch_metadata.items_fetched + excluded.items_fetched,
      next_start_index = excluded.next_start_index
  `;

  try {
    const startTime = Date.now();
    await d1.prepare(sql)
      .bind(source, fetchTime, fetchTime, 0, nextStartIndex)
      .run();
    
    console.log('[D1] Successfully updated fetch metadata:', {
      duration: `${Date.now() - startTime}ms`,
      newStartIndex: nextStartIndex
    });
  } catch (error) {
    console.error('[D1] Failed to update fetch metadata:', {
      error: error.message,
      sql: sql,
      params: {source, fetchTime, nextStartIndex},
      code: error.code,
      stack: error.stack
    });
    throw error; // Propagate error up
  }
}