import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js";

export default {
  async fetch(request, env) {
    const startTime = Date.now();
    console.log('[Worker] Request received:', request.url);
    await sendToLogQueue(env, {
      level: 'info',
      message: 'Worker request received',
      data: { url: request.url, timestamp: new Date().toISOString() }
    });

    const fauna = new Client({ secret: env.FAUNA_SECRET });
    const url = new URL(request.url);

    try {
      if (url.pathname === '/fetchnvd') {
        console.log('[Worker] Initiating NVD data fetch');
        await sendToLogQueue(env, {
          level: 'info',
          message: 'Starting NVD data fetch',
          data: { timestamp: new Date().toISOString() }
        });

        await fetchNvdData(env, fauna);
        
        const duration = Date.now() - startTime;
        console.log(`[Worker] Completed successfully in ${duration}ms`);
        await sendToLogQueue(env, {
          level: 'info',
          message: 'Worker completed successfully',
          data: { duration, timestamp: new Date().toISOString() }
        });

        return new Response('NVD data fetched successfully.', { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    } catch (error) {
      console.error('[Worker] Error:', error);
      await sendToLogQueue(env, {
        level: 'error',
        message: 'Worker error',
        data: { error: error.message, stack: error.stack }
      });
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

async function fetchNvdData(env, fauna) {
  const startTime = Date.now();
  let response, responseText;
  let hasMoreData = true;
  let startIndex = 0;
  let processedCount = 0;
  let errorCount = 0;

  const now = new Date();
  now.setDate(now.getDate() - 5);
  const lastModStartDate = now.toISOString();
  const lastModEndDate = new Date().toISOString();

  console.log('[NVD] Starting data fetch cycle');
  await sendToLogQueue(env, {
    level: 'info',
    message: 'Starting NVD fetch cycle',
    data: { lastModStartDate, lastModEndDate }
  });

  while (hasMoreData) {
    const requestURL = `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000`
      + `&startIndex=${startIndex}&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`;

    try {
      console.log('[NVD] Requesting:', requestURL);
      await sendToLogQueue(env, {
        level: 'info',
        message: 'NVD API request',
        data: { url: requestURL, startIndex }
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
          message: 'NVD API error',
          data: { status: response.status, body: errorBody }
        });
        break;
      }

      responseText = await response.text();
      const responseData = JSON.parse(responseText);

      if (responseData?.vulnerabilities?.length > 0) {
        console.log(`[NVD] Processing ${responseData.vulnerabilities.length} vulnerabilities`);
        await sendToLogQueue(env, {
          level: 'info',
          message: 'Processing vulnerabilities batch',
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
    } catch (e) {
      errorCount++;
      console.error('[NVD] Request failed:', e);
      await sendToLogQueue(env, {
        level: 'error',
        message: 'NVD request failed',
        data: { error: e.message, startIndex }
      });
      break;
    }
  }

  const duration = Date.now() - startTime;
  console.log(`[NVD] Completed fetch cycle. Processed: ${processedCount}, Errors: ${errorCount}, Duration: ${duration}ms`);
  await sendToLogQueue(env, {
    level: 'info',
    message: 'Completed NVD fetch cycle',
    data: { processedCount, errorCount, duration }
  });
}

async function processVulnerabilityItem(item, env) {
  if (!item?.cve?.id) {
    console.warn('[NVD] Invalid CVE entry:', item);
    await sendToLogQueue(env, {
      level: 'warn',
      message: 'Invalid CVE entry',
      data: { item }
    });
    return null;
  }
  return item;
}

async function storeVulnerabilitiesInFaunaDB(vulnerabilities, fauna, env) {
  if (!vulnerabilities?.length) return;

  console.log(`[FaunaDB] Processing ${vulnerabilities.length} items`);
  await sendToLogQueue(env, {
    level: 'info',
    message: 'Starting FaunaDB operations',
    data: { count: vulnerabilities.length }
  });

  try {
    // First create collection if it doesn't exist
    console.log('[FaunaDB] Ensuring collection exists');
    await fauna.query(
      fql`If(!Exists(Collection("Vulnerabilities")),
        CreateCollection({ name: "Vulnerabilities" }))`
    );

    let successCount = 0;
    let errorCount = 0;

    for (const vuln of vulnerabilities) {
      try {
        console.log(`[FaunaDB] Processing CVE: ${vuln.cve.id}`);
        
        // Simplified query structure
        const result = await fauna.query(
          fql`
            Create(
              Collection("Vulnerabilities"),
              {
                data: {
                  cveId: ${vuln.cve.id},
                  sourceData: ${vuln},
                  createdAt: Now(),
                  updatedAt: Now()
                }
              }
            )
          `
        );

        successCount++;
        console.log(`[FaunaDB] Successfully stored: ${vuln.cve.id}`);
        await sendToLogQueue(env, {
          level: 'info',
          message: 'FaunaDB store success',
          data: { cveId: vuln.cve.id }
        });
      } catch (error) {
        errorCount++;
        console.error(`[FaunaDB] Error storing ${vuln.cve.id}:`, error);
        await sendToLogQueue(env, {
          level: 'error',
          message: 'FaunaDB store error',
          data: {
            cveId: vuln.cve.id,
            error: error.message,
            validationErrors: error.errors,
            stack: error.stack
          }
        });
      }
    }

    console.log(`[FaunaDB] Batch complete - Success: ${successCount}, Errors: ${errorCount}`);
    await sendToLogQueue(env, {
      level: 'info',
      message: 'FaunaDB batch complete',
      data: { successCount, errorCount }
    });

  } catch (error) {
    console.error('[FaunaDB] Fatal error:', error);
    await sendToLogQueue(env, {
      level: 'error',
      message: 'Fatal FaunaDB error',
      data: {
        error: error.message,
        validationErrors: error.errors,
        stack: error.stack
      }
    });
    throw error;
  }
}