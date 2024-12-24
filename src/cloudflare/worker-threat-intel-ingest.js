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

  await sendToLogQueue(env, {
    level: "info",
    message: "Starting NVD fetch process",
    data: { lastFetchTime, lastModStartDate, lastModEndDate },
  });

  while (hasMoreData) {
    const requestURL =
      `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=${pageSize}` +
      `&startIndex=${startIndex}` +
      `&lastModStartDate=${lastModStartDate}` +
      `&lastModEndDate=${lastModEndDate}`;

    // More detailed logging of requestURL
    await sendToLogQueue(env, {
      level: "debug",
      message: "Fetching NVD data page",
      data: { requestURL, startIndex, pageSize, hasMoreData },
    });

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

    // Log raw status before checking response.ok
    await sendToLogQueue(env, {
      level: "debug",
      message: "NVD API response",
      data: { status: response.status, ok: response.ok },
    });

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

    // Add total entries logging
    const totalEntries = responseData.totalResults;
    console.log(`[NVD] Total entries to process: ${totalEntries}`);
    await sendToLogQueue(env, {
      level: "info",
      message: "Starting NVD data processing",
      data: {
        totalEntries,
        batchSize: pageSize,
        estimatedBatches: Math.ceil(totalEntries / pageSize),
        startTime: new Date().toISOString()
      }
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

      // Log the number of vulnerabilities processed in this batch
      await sendToLogQueue(env, {
        level: "debug",
        message: "Vulnerabilities processed for this page",
        data: { processedCount: processedData.length },
      });

      // Add progress logging
      const progress = ((startIndex / totalEntries) * 100).toFixed(2);
      console.log(`[NVD] Processing batch ${Math.floor(startIndex/pageSize) + 1}/${Math.ceil(totalEntries/pageSize)} (${progress}%)`);
      await sendToLogQueue(env, {
        level: "debug",
        message: "Processing NVD batch",
        data: {
          batchNumber: Math.floor(startIndex/pageSize) + 1,
          totalBatches: Math.ceil(totalEntries/pageSize),
          progress: `${progress}%`,
          entriesProcessed: startIndex,
          totalEntries
        }
      });

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
    message: "Finished fetching NVD data",
    data: { finalStartIndex: startIndex, source },
  });

  // Add final statistics
  await sendToLogQueue(env, {
    level: "info",
    message: "Completed NVD data processing",
    data: {
      totalEntriesProcessed: startIndex,
      totalAvailable: totalEntries,
      completionTime: new Date().toISOString(),
      processingDuration: `${((Date.now() - startTime)/1000).toFixed(2)}s`
    }
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
  // Try CVSS v3.1 first, fall back to v2 if not available
  const metricsV31 = cveData.metrics?.cvssMetricV31?.[0]?.cvssData;
  const metricsV2 = cveData.metrics?.cvssMetricV2?.[0]?.cvssData;
  
  // Use v3.1 if available, otherwise use v2
  const metrics = metricsV31 || metricsV2 || {};
  
  console.log(`[Process] Processing CVE ${cveData.id} - CVSS v3.1: ${!!metricsV31}, CVSS v2: ${!!metricsV2}`);

  return {
    cveId: cveData.id,
    link: `https://nvd.nist.gov/vuln/detail/${cveData.id}`,
    description: cveData.descriptions?.find((d) => d.lang === "en")?.value || "",
    source: cveData.sourceIdentifier || "NVD",
    published: cveData.published || null,
    lastModified: cveData.lastModified || null,
    baseScore: metrics.baseScore || null,
    baseSeverity: metricsV31?.baseSeverity || cveData.metrics?.cvssMetricV2?.[0]?.baseSeverity || null,
    vectorString: metrics.vectorString || null,
    cwe: cveData.weaknesses?.[0]?.description?.[0]?.value || null,
    refUrls: JSON.stringify(cveData.references?.map((ref) => ref.url) || []),
    fetched_at: new Date().toISOString(),
  };
}

/**
 * Store NVD vulnerabilities in Cloudflare D1 database
 */
async function storeVulnerabilitiesInD1(d1, vulnerabilities, env) {
  const startTime = Date.now();
  console.log(`[D1] Starting to store ${vulnerabilities.length} vulnerabilities`);
  
  try {
    if (!vulnerabilities?.length) {
      console.log('[D1] No vulnerabilities to store');
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

    let successCount = 0;
    let updateCount = 0;
    let skipCount = 0;

    for (const vuln of vulnerabilities) {
      if (!vuln.cveId) {
        console.log(`[D1] Skipping invalid vulnerability: ${JSON.stringify(vuln)}`);
        skipCount++;
        continue;
      }

      console.log(`[D1] Processing vulnerability: ${vuln.cveId}`);
      
      try {
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
        console.log(`[D1] Successfully stored/updated: ${vuln.cveId}`);
        
        await sendToLogQueue(env, {
          level: "debug",
          message: `Processed vulnerability ${vuln.cveId}`,
          data: {
            cveId: vuln.cveId,
            baseScore: vuln.baseScore,
            baseSeverity: vuln.baseSeverity,
            published: vuln.published,
            lastModified: vuln.lastModified
          }
        });
      } catch (error) {
        console.error(`[D1] Error processing ${vuln.cveId}:`, error);
        await sendToLogQueue(env, {
          level: "error",
          message: `Failed to process vulnerability ${vuln.cveId}`,
          data: {
            error: error.message,
            stack: error.stack,
            vulnerability: vuln
          }
        });
      }
    }

    const duration = Date.now() - startTime;
    console.log(`[D1] Storage complete - Success: ${successCount}, Skipped: ${skipCount}, Duration: ${duration}ms`);

    await sendToLogQueue(env, {
      level: "info",
      message: `Stored vulnerabilities in D1 successfully`,
      data: {
        total: vulnerabilities.length,
        success: successCount,
        skipped: skipCount,
        duration,
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    const duration = Date.now() - startTime;
    console.error(`[D1] Fatal error storing vulnerabilities:`, error);
    
    await sendToLogQueue(env, {
      level: "error",
      message: `Error in storeVulnerabilitiesInD1`,
      data: {
        error: error.message,
        stack: error.stack,
        duration,
        timestamp: new Date().toISOString(),
        vulnerabilitiesCount: vulnerabilities?.length
      }
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
      .prepare(`SELECT last_fetch_time FROM fetch_metadata WHERE source = ?`)
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
