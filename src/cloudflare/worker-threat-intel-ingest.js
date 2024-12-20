import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js";

export default {
  async fetch(request, env) {
    const fauna = new Client({ secret: env.FAUNA_SECRET });
    const url = new URL(request.url);

    try {
      if (url.pathname === '/fetchnvd') {
        await fetchNvdData(env, fauna);
        return new Response('NVD data fetched successfully.', { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    } catch (error) {
      await sendToLogQueue(env, {
        level: 'error',
        message: `Error fetching data: ${error.message}`,
        stack: error.stack,
      });
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

async function fetchNvdData(env, fauna) {
  let response, responseText;
  let hasMoreData = true;
  let startIndex = 0;

  // Example incremental approach
  const now = new Date();
  now.setDate(now.getDate() - 1);
  const lastModStartDate = now.toISOString();
  const lastModEndDate = new Date().toISOString();

  while (hasMoreData) {
    const requestURL = `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000`
      + `&startIndex=${startIndex}&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`;

    try {
      response = await fetch(requestURL, {
        headers: {
          'Accept': 'application/json',
          'apiKey': env.NVD_API_KEY,
        },
      });
      if (!response.ok) {
        const errorBody = await response.text();
        await sendToLogQueue(env, {
          level: 'error',
          message: 'NVD API Error',
          data: { status: response.status, body: errorBody },
        });
        break;
      }
    } catch (e) {
      await sendToLogQueue(env, {
        level: 'error',
        message: 'NVD API request failed',
        data: { error: e.message, requestURL },
      });
      break;
    }

    responseText = await response.text();
    const responseData = JSON.parse(responseText);

    if (responseData?.vulnerabilities?.length > 0) {
      const validItems = [];

      for (const item of responseData.vulnerabilities) {
        const validated = processVulnerabilityItem(item, env);
        if (validated) validItems.push(validated);
      }

      await storeVulnerabilitiesInFaunaDB(validItems, fauna, env);

      startIndex += responseData.resultsPerPage;
      hasMoreData = startIndex < responseData.totalResults;
    } else {
      hasMoreData = false;
    }
  }

  await sendToLogQueue(env, {
    level: 'info',
    message: 'Completed NVD fetch cycle.',
  });
}

function processVulnerabilityItem(item, env) {
  if (!item?.cve?.id) {
    sendToLogQueue(env, {
      level: 'warn',
      message: 'Skipping invalid CVE entry',
      data: { item },
    });
    return null;
  }
  // Returns the entire JSON object as is
  return item;
}

async function storeVulnerabilitiesInFaunaDB(vulnerabilities, fauna, env) {
  if (!vulnerabilities?.length) return;

  for (const vuln of vulnerabilities) {
    try {
      // Insert into the "Vulnerabilities" collection.
      const query_create = fql`Vulnerabilities.create({ data: ${vuln} })`;
      await fauna.query(query_create);
    } catch (error) {
      await sendToLogQueue(env, {
        level: 'error',
        message: `Error inserting vulnerability into FaunaDB: ${error.message}`,
        data: vuln,
      });
    }
  }

  await sendToLogQueue(env, {
    level: 'info',
    message: 'Vulnerabilities stored in FaunaDB successfully.',
  });
}