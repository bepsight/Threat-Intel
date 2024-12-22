import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js";

// The main entry point for your worker:
export default {
  async fetch(request, env) {
    const startTime = Date.now();

    console.log('[Worker] Request received:', request.url);
    await sendToLogQueue(env, {
      level: 'info',
      message: '[Worker] Request received',
      data: { url: request.url, timestamp: new Date().toISOString() }
    });

    const fauna = new Client({ secret: env.FAUNA_SECRET });
    const url = new URL(request.url);

    try {
      if (url.pathname === '/fetchnvd') {
        console.log('[Worker] Initiating NVD data fetch');
        await sendToLogQueue(env, {
          level: 'info',
          message: '[Worker] Starting NVD data fetch',
          data: { timestamp: new Date().toISOString() }
        });

        await fetchNvdData(env, fauna);

        const duration = Date.now() - startTime;
        console.log(`[Worker] Completed successfully in ${duration}ms`);
        await sendToLogQueue(env, {
          level: 'info',
          message: '[Worker] Completed successfully',
          data: { duration, timestamp: new Date().toISOString() }
        });

        return new Response('NVD data fetched successfully.', { status: 200 });
      } else {
        console.log('[Worker] Not Found:', url.pathname);
        await sendToLogQueue(env, {
          level: 'warn',
          message: '[Worker] Route not found',
          data: { pathname: url.pathname }
        });
        return new Response('Not Found', { status: 404 });
      }
    } catch (error) {
      console.error('[Worker] Error:', error);
      await sendToLogQueue(env, {
        level: 'error',
        message: '[Worker] Error',
        data: { error: error.message, stack: error.stack }
      });
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

/**
 * 1) Fetches NVD data in pages.
 * 2) Processes each item to ensure it’s valid JSON for Fauna.
 * 3) Stores it in FaunaDB.
 */
async function fetchNvdData(env, fauna) {
  const startTime = Date.now();
  let response;
  let hasMoreData = true;
  let startIndex = 0;
  let processedCount = 0;
  let errorCount = 0;

  // Set date window (past 5 days)
  const now = new Date();
  now.setDate(now.getDate() - 5);
  const lastModStartDate = now.toISOString();
  const lastModEndDate = new Date().toISOString();

  console.log('[NVD] Starting data fetch cycle');
  await sendToLogQueue(env, {
    level: 'info',
    message: '[NVD] Starting data fetch cycle',
    data: { lastModStartDate, lastModEndDate }
  });

  while (hasMoreData) {
    const requestURL = `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000` +
      `&startIndex=${startIndex}&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`;

    try {
      console.log('[NVD] Requesting:', requestURL);
      await sendToLogQueue(env, {
        level: 'info',
        message: '[NVD] Requesting data',
        data: { requestURL, startIndex }
      });

      response = await fetch(requestURL, {
        headers: {
          'Accept': 'application/json',
          'apiKey': env.NVD_API_KEY,
        },
      });

      if (!response.ok) {
        const errorBody = await response.text();
        console.error('[NVD] API Error:', response.status, errorBody);
        await sendToLogQueue(env, {
          level: 'error',
          message: '[NVD] API Error',
          data: { status: response.status, body: errorBody }
        });
        break;
      }

      const responseText = await response.text();
      const responseData = JSON.parse(responseText);

      if (responseData?.vulnerabilities?.length > 0) {
        console.log(`[NVD] Processing ${responseData.vulnerabilities.length} vulnerabilities`);
        await sendToLogQueue(env, {
          level: 'info',
          message: '[NVD] Processing vulnerabilities',
          data: { count: responseData.vulnerabilities.length, startIndex }
        });

        const validItems = [];
        for (const item of responseData.vulnerabilities) {
          const validated = processVulnerabilityItem(item, env);
          if (validated) validItems.push(validated);
        }

        await storeVulnerabilitiesInFaunaDB(validItems, fauna, env);

        processedCount += validItems.length;
        startIndex += responseData.resultsPerPage;
        hasMoreData = startIndex < responseData.totalResults;
      } else {
        hasMoreData = false;
      }

    } catch (err) {
      errorCount++;
      console.error('[NVD] Request failed:', err);
      await sendToLogQueue(env, {
        level: 'error',
        message: '[NVD] Request failed',
        data: { error: err.message, stack: err.stack, startIndex }
      });
      break;
    }
  }

  const duration = Date.now() - startTime;
  console.log(`[NVD] Completed fetch cycle. Processed: ${processedCount}, Errors: ${errorCount}, Duration: ${duration}ms`);
  await sendToLogQueue(env, {
    level: 'info',
    message: '[NVD] Completed fetch cycle',
    data: { processedCount, errorCount, duration }
  });
}

/**
 * Safely transform any invalid JSON data:
 * - Replaces `Boolean` constructor with literal `false`
 * - Replaces `undefined` with `null`
 */
function sanitizeForFauna(obj) {
  return JSON.parse(JSON.stringify(obj, (key, value) => {
    // If the raw data literally had `Boolean`, replace it with `false`
    if (value === Boolean) {
      return false;
    }
    // Convert undefined → null
    if (typeof value === 'undefined') {
      return null;
    }
    return value; 
  }));
}

/**
 * Extracts the minimal fields we need, then sanitizes the data.
 */
function processVulnerabilityItem(item, env) {
  // Must have an ID
  if (!item?.cve?.id) {
    console.warn('[NVD] Invalid CVE entry:', item);
    sendToLogQueue(env, {
      level: 'warn',
      message: '[NVD] Invalid CVE entry',
      data: { item }
    });
    return null;
  }

  // Return a clean object
  return {
    cve_id: item.cve.id,
    sourceData: sanitizeForFauna(item),
  };
}

/**
 * Stores each vulnerability in FaunaDB:
 * - Creates the collection if missing
 * - Either creates a new doc or updates existing by cve_id
 */
async function storeVulnerabilitiesInFaunaDB(vulnerabilities, fauna, env) {
  if (!Array.isArray(vulnerabilities) || vulnerabilities.length === 0) {
    console.log('[FaunaDB] No vulnerabilities to process.');
    return;
  }

  console.log(`[FaunaDB] Processing ${vulnerabilities.length} items`);
  await sendToLogQueue(env, {
    level: 'info',
    message: '[FaunaDB] Processing items',
    data: { count: vulnerabilities.length }
  });

  let successCount = 0;
  let errorCount = 0;

  // Ensure the collection exists
  try {
    console.log('[FaunaDB] Ensuring collection exists');
    const collectionResult = await fauna.query(
      fql`
        if (!Collection.byName("Vulnerabilities").exists()) {
          Collection.create({ name: "Vulnerabilities" })
        } else {
          "collection_exists"
        }
      `
    );
    console.log('[FaunaDB] Collection ensure result:', collectionResult);
    await sendToLogQueue(env, {
      level: 'info',
      message: '[FaunaDB] Collection ensure result',
      data: { collectionResult }
    });
  } catch (error) {
    console.error('[FaunaDB] Fatal error ensuring collection:', error);
    await sendToLogQueue(env, {
      level: 'error',
      message: '[FaunaDB] Fatal error ensuring collection',
      data: { error: error.message, stack: error.stack }
    });
    throw error;
  }

  // Create/update each vulnerability
  for (const vuln of vulnerabilities) {
    try {
      console.log(`[FaunaDB] Attempting to store vulnerability: ${vuln.cve_id}`);
      const createResult = await fauna.query(
        fql`
          let cveMatch = Vulnerabilities.vulnerabilities_by_cve_id(${vuln.cve_id}).first()

          if (cveMatch == null) {
            Vulnerabilities.create({ data: ${vuln} })
          } else {
            cveMatch!.update({ data: ${vuln} })
          }
        `
      );
      successCount++;
      console.log(`[FaunaDB] Successfully stored: ${vuln.cve_id}`, createResult);
      await sendToLogQueue(env, {
        level: 'info',
        message: '[FaunaDB] Store success',
        data: { cveId: vuln.cve_id, createResult }
      });

    } catch (error) {
      errorCount++;
      console.error(`[FaunaDB] Store error for ${vuln.cve_id}:`, error.queryInfo?.summary || error.message);
      await sendToLogQueue(env, {
        level: 'error',
        message: '[FaunaDB] Store error',
        data: {
          cveId: vuln.cve_id,
          error: error.message,
          stack: error.stack
        }
      });
    }
  }

  console.log(`[FaunaDB] Batch complete - Success: ${successCount}, Errors: ${errorCount}`);
  await sendToLogQueue(env, {
    level: 'info',
    message: '[FaunaDB] Batch complete',
    data: { successCount, errorCount }
  });
}
