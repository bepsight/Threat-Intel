import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js"; // Import custom log function

export default {
  async fetch(request, env, ctx) {
    const d1 = env.THREAT_INTEL_DB; // Get D1 binding from environment
    const fauna = new Client({
      secret: env.FAUNA_SECRET, // Get Fauna secret from environment
    });

    const url = new URL(request.url);

    try {
      if (url.pathname === '/fetchmisp') {
        // Fetch MISP data
        await fetchThreatIntelData(env, d1, 'misp');
        return new Response('MISP data fetched successfully.', { status: 200 });
      } else if (url.pathname === '/fetchnvd') {
        // Fetch NVD data
        await fetchThreatIntelData(env, d1, 'nvd');
        return new Response('NVD data fetched successfully.', { status: 200 });
      } else if (url.pathname === '/fetchrss') {
        // Fetch RSS data
        await fetchThreatIntelData(env, d1, 'rss');
        return new Response('RSS data fetched successfully.', { status: 200 });
      } 
    } catch (error) {
      // Log the error
      await sendToLogQueue(env, {
        level: 'error',
        message: `Error fetching data: ${error.message}`,
        stack: error.stack,
      });
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

async function fetchThreatIntelData(env, d1, type) {
  let response;
  let responseText;
  let data = [];

  try {
    let url = '';
    let lastFetchTime = null;
    let allData = [];

    if (type === 'misp') {
      url = 'https://simp.xsight.network/events/restSearch';
      lastFetchTime = await getLastFetchTime(d1, url, env);

      let requestBody = {
        limit: 50,
        page: 1,
        includeAttributes: true,
        includeContext: true,
        returnFormat: 'json',
      };

      if (lastFetchTime) {
        requestBody.from = new Date(lastFetchTime).toISOString();
      } else {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        requestBody.from = thirtyDaysAgo.toISOString();
      }

      let hasMoreData = true;
      while (hasMoreData) {
        await sendToLogQueue(env, {
          level: 'info',
          message: `Fetching page ${requestBody.page} from MISP`,
        });

        response = await fetch(url, {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': env.MISP_API_KEY,
          },
          body: JSON.stringify(requestBody),
        });

        responseText = await response.text();

        if (response.ok) {
          const responseData = JSON.parse(responseText);
          if (responseData && responseData.response) {
            if (Array.isArray(responseData.response)) {
              allData.push(...responseData.response);
            } else {
              allData.push(responseData.response);
            }
            if (responseData.response.length < requestBody.limit) {
              hasMoreData = false;
            } else {
              requestBody.page += 1;
            }
          } else {
            hasMoreData = false;
          }
        } else {
          await sendToLogQueue(env, {
            level: 'error',
            message: `Failed to fetch misp data: ${response.status} ${response.statusText}`,
            responseBody: responseText,
          });
          throw new Error(`Failed to fetch misp data: ${response.status} ${response.statusText}`);
        }
      }
      data = allData;

    } else if (type === 'nvd') {
      url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/';
      lastFetchTime = await getLastFetchTime(d1, url, env);

      let hasMoreData = true;
      let startIndex = 0;
      let lastModStartDate = null;
      let lastModEndDate = null;

      if (lastFetchTime) {
        lastModStartDate = new Date(lastFetchTime).toISOString();
        lastModEndDate = new Date().toISOString();
      } else {
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        lastModStartDate = thirtyDaysAgo.toISOString();
        lastModEndDate = new Date().toISOString();
      }

      while (hasMoreData) {
        let requestURL = `${url}?resultsPerPage=2000&startIndex=${startIndex}`;
        requestURL += `&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`;

        await sendToLogQueue(env, {
          level: 'info',
          message: `Fetching NVD data from ${requestURL}.`,
        });

        response = await fetch(requestURL, {
          headers: {
            'Accept': 'application/json',
            'apiKey': env.NVD_API_KEY,
          },
        });

        responseText = await response.text();

        if (response.ok) {
          const responseData = JSON.parse(responseText);
          if (responseData && responseData.vulnerabilities) {
            allData.push(...responseData.vulnerabilities);
            startIndex += responseData.resultsPerPage;
            if (startIndex >= responseData.totalResults) {
              hasMoreData = false;
            }
          } else {
            hasMoreData = false;
          }
        } else {
          await sendToLogQueue(env, {
            level: 'error',
            message: `Failed to fetch nvd data: ${response.status} ${response.statusText}`,
            responseBody: responseText,
          });
          throw new Error(`Failed to fetch nvd data: ${response.status} ${response.statusText}`);
        }
      }
      data = allData;

    } else if (type === 'rss') {
      url = 'https://your-rss-feed-url.com/rss';
      lastFetchTime = null;

      await sendToLogQueue(env, {
        level: 'info',
        message: `Fetching RSS data from ${url}.`,
      });

      response = await fetch(`${url}?limit=100`, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${env.RSS_API_KEY}:${env.RSS_API_SECRET}`,
        },
      });

      responseText = await response.text();

      if (response.ok) {
        const responseData = JSON.parse(responseText);
        if (responseData && responseData.data && Array.isArray(responseData.data)) {
          for (const feed of responseData.data) {
            if (feed && feed.items && Array.isArray(feed.items)) {
              allData.push(...feed.items);
            }
          }
        }
        data = allData;
      } else {
        await sendToLogQueue(env, {
          level: 'error',
          message: `Failed to fetch rss data: ${response.status} ${response.statusText}`,
          responseBody: responseText,
        });
        throw new Error(`Failed to fetch rss data: ${response.status} ${response.statusText}`);
      }
    } else {
      throw new Error(`Unsupported feed type: ${type}`);
    }

    // Process and store data
    await processAndStoreData(env, d1, data, type, url, lastFetchTime);

    await sendToLogQueue(env, {
      level: 'info',
      message: `Successfully fetched ${type} data from ${url}.`,
    });

  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error fetching ${type} data: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

// Function to filter relevant threat intel
function filterRelevantThreatIntel(stixObjects) {
  // Filter and process the stix objects
  const relevantIndicators = [];
  stixObjects.forEach((object) => {
    if (object.type === "indicator" && object.pattern_type === "stix") {
      // Example pattern matching using regex
      const ipRegex = /\[ipv4-addr:value = '(.*?)'\]/;

      const matchIP = object.pattern.match(ipRegex);
      if (matchIP && matchIP[1]) {
        relevantIndicators.push({
          type: "ip",
          value: matchIP[1],
          labels: object.labels,
          description: object.description,
          timestamp: object.modified,
          confidence: object.confidence,
        });
      }
      const ipV6Regex = /\[ipv6-addr:value = '(.*?)'\]/;
      const matchIPv6 = object.pattern.match(ipV6Regex);
      if (matchIPv6 && matchIPv6[1]) {
        relevantIndicators.push({
          type: "ip",
          value: matchIPv6[1],
          labels: object.labels,
          description: object.description,
          timestamp: object.modified,
          confidence: object.confidence,
        });
      }
    }
    //Extract Vulnerability Data
    if (object.type === "vulnerability") {
      const vulnerability = {
        type: "vulnerability",
        cve:
          object.external_references &&
          object.external_references.find((ref) => ref.source_name === "cve")
            ?.external_id,
        name: object.name,
        description: object.description,
        labels: object.labels,
        modified: object.modified,
      };
      relevantIndicators.push(vulnerability);
    }

    //Extract Software Data
    if (object.type === "software") {
      relevantIndicators.push({
        type: "software",
        name: object.name,
        cpe: object.cpe,
        labels: object.labels,
        description: object.description,
        modified: object.modified,
      });
    }
    //Filter for Malware and Tools related to software and infrastructure component
    if (object.type === "malware" || object.type === "tool") {
      relevantIndicators.push({
        type: object.type,
        name: object.name,
        labels: object.labels,
        description: object.description,
        modified: object.modified,
      });
    }
  });

  return relevantIndicators;
}

// Function to store data in D1
async function storeInD1(d1, data, env) {
  try {
    console.log("Storing data in D1");
    for (const threat of data) {
      const searchableText = `${threat.type} ${
        threat.value || ""
      } ${threat.description || ""} ${threat.cve || ""} ${
        threat.name || ""
      } ${threat.cpe || ""}`;
      await d1
        .prepare(
          "INSERT INTO threat_intel (type, value, labels, description, timestamp , confidence, cve, name, cpe, modified, searchable_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(
          threat.type,
          threat.value || null,
          JSON.stringify(threat.labels) || null,
          threat.description || null,
          threat.timestamp || null,
          threat.confidence || null,
          threat.cve || null,
          threat.name || null,
          threat.cpe || null,
          threat.modified || null,
          searchableText
        )
        .run();
    }
    await sendToLogQueue(env, {
      level: "info",
      message: "Threat intel data stored in D1 successfully.",
    });
      console.log("Data stored in D1 successfully");
  } catch (error) {
    await sendToLogQueue(env, {
      level: "error",
      message: `Error storing threat intel in D1: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function storeInFaunaDB(data, fauna, env) {
    // Implement FaunaDB storage
     try {
        for (const threat of data) {
          const query_create = fql`Threats.create({ data: ${threat} })`;
          await fauna.query(query_create);
         }
         await sendToLogQueue(env, {
            level: "info",
            message: "Threat intel data stored in FaunaDB successfully.",
        });
        console.log("Data stored in FaunaDB successfully");

    } catch (error) {
        await sendToLogQueue(env, {
            level: "error",
            message: `Error storing threat intel in FaunaDB: ${error.message}`,
            stack: error.stack,
       });
         throw error;
    }
}

async function getLastFetchTime(d1, resourceUrl, env) {
  try {
    const { results } = await d1
      .prepare("SELECT last_fetch_time FROM fetch_stats WHERE resource_url = ?")
      .bind(resourceUrl)
      .all();

    if (results && results.length > 0 && results[0].last_fetch_time) {
      await sendToLogQueue(env, {
        level: 'info',
        message: `Last fetch time found for resource: ${resourceUrl}. Time: ${results[0].last_fetch_time}.`,
      });
      return results[0].last_fetch_time;
    }

    await sendToLogQueue(env, {
      level: 'info',
      message: `Last fetch time not found for resource: ${resourceUrl}. Returning null.`,
    });
    return null;
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error getting last fetch time from D1 for resource: ${resourceUrl}. ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function updateLastFetchTime(d1, resourceUrl, fetchTime, env) {
  try {
    await d1
      .prepare(
        `INSERT INTO fetch_stats (resource_url, last_fetch_time, fetch_count)
         VALUES (?, ?, COALESCE((SELECT fetch_count FROM fetch_stats WHERE resource_url = ?) + 1, 1))
         ON CONFLICT(resource_url) DO UPDATE SET
           last_fetch_time = excluded.last_fetch_time,
           fetch_count = fetch_stats.fetch_count + 1`
      )
      .bind(resourceUrl, fetchTime, resourceUrl)
      .run();

    await sendToLogQueue(env, {
      level: 'info',
      message: `Last fetch time updated in D1 for resource: ${resourceUrl}. Time: ${fetchTime}.`,
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error updating last fetch time in D1 for resource: ${resourceUrl}. ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function processAndStoreData(env, d1, data, type, url, lastFetchTime) {
  const fauna = new Client({
    secret: env.FAUNA_SECRET,
  });

  try {
    let processedData = [];

    // Process data based on feed type
    if (type === 'misp') {
      // For MISP data, apply filtering for STIX type feeds
      const relevantIndicators = filterRelevantThreatIntel(data);
      processedData = relevantIndicators;
      console.log(`Processed ${relevantIndicators.length} relevant indicators from MISP feed.`);
    } else if (type === 'nvd') {
      // Process NVD data to match the vulnerabilities table schema
      processedData = data.map((item) => {
        const cveItem = item.cve;
        const title = cveItem.cveMetadata.cveId;
        const link = `https://nvd.nist.gov/vuln/detail/${cveItem.cveMetadata.cveId}`;
        const description =
          cveItem.descriptions && cveItem.descriptions.length > 0
            ? cveItem.descriptions[0].value
            : '';
        const source = 'NVD';
        const pub_date = cveItem.published
          ? cveItem.published
          : new Date().toISOString();
        const fetched_at = new Date().toISOString();

        return {
          title,
          link,
          description,
          source,
          pub_date,
          fetched_at,
        };
      });

      console.log(`Processed ${processedData.length} vulnerabilities from NVD feed.`);
    } else if (type === 'rss') {
      // For RSS data, process as needed
      processedData = data; // Assuming data is already in desired format
      console.log(`Processed ${data.length} items from RSS feed.`);
    } else {
      throw new Error(`Unsupported feed type: ${type}`);
    }

    // Store processed data in D1
    if (processedData.length > 0) {
      if (type === 'nvd') {
        await storeVulnerabilitiesInD1(d1, processedData, env);
      } else {
        await storeInD1(d1, processedData, env);
        await storeInFaunaDB(processedData, fauna, env);
      }
    } else {
      console.log('No data to store after processing.');
    }

    // Update last fetch time in D1
    const fetchTime = new Date().toISOString();
    await updateLastFetchTime(d1, url, fetchTime, env);

    await sendToLogQueue(env, {
      level: 'info',
      message: `Successfully processed and stored data from ${type} feed.`,
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error processing data from ${type} feed: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function storeVulnerabilitiesInD1(d1, vulnerabilities, env) {
  try {
    console.log('Storing vulnerabilities in D1');
    for (const vuln of vulnerabilities) {
      await d1
        .prepare(
          'INSERT INTO vulnerabilities (title, link, description, source, pub_date, fetched_at) VALUES (?, ?, ?, ?, ?, ?)'
        )
        .bind(
          vuln.title,
          vuln.link,
          vuln.description,
          vuln.source,
          vuln.pub_date,
          vuln.fetched_at
        )
        .run();
    }
    await sendToLogQueue(env, {
      level: 'info',
      message: 'Vulnerabilities data stored in D1 successfully.',
    });
    console.log('Vulnerabilities stored in D1 successfully');
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error storing vulnerabilities in D1: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}