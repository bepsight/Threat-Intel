import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js";

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

async function fetchNvdData(env, fauna) {
  const startTime = Date.now();
  let response;
  let hasMoreData = true;
  let startIndex = 0;
  let processedCount = 0;
  let errorCount = 0;

  // Set date window
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

      if (responseData?.vulnerabilities && responseData.vulnerabilities.length > 0) {
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

function processVulnerabilityItem(item, env) {
  if (!item?.cve?.id) {
    console.warn('[NVD] Invalid CVE entry:', item);
    sendToLogQueue(env, {
      level: 'warn',
      message: '[NVD] Invalid CVE entry',
      data: { item }
    });
    return null;
  }

  // Ensure consistent structure:
    const processedItem = {
        cve: {
            id: item.cve.id,
            // ... add other cve properties you need
        },
        // ... add other top-level properties from item that you require
        sourceData: item, // Keep original data if needed for debugging
    };

    return processedItem;
}

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

  for (const vuln of vulnerabilities) {
    try {
      console.log(`[FaunaDB] Storing vulnerability: ${vuln.cve.id}`);
      await fauna.query(
        fql`
          Collection.byName("Vulnerabilities").create({
            data: ${vuln}
          })
        `
      );
      successCount++;
      console.log(`[FaunaDB] Successfully stored: ${vuln.cve.id}`);
      await sendToLogQueue(env, {
        level: 'info',
        message: '[FaunaDB] Store success',
        data: { cveId: vuln.cve.id }
      });
    } catch (error) {
      errorCount++;
      console.error(`[FaunaDB] Store error for ${vuln.cve.id}:`, error);
      await sendToLogQueue(env, {
        level: 'error',
        message: '[FaunaDB] Store error',
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
    message: '[FaunaDB] Batch complete',
    data: { successCount, errorCount }
  });
}
