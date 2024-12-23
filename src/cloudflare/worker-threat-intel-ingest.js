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
  let data_retention_days = 1;

  try {
    let url = '';
    let lastFetchTime = null;
    let allData = [];

    if (type === 'nvd') {
      url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/';
      lastFetchTime = await getLastFetchTime(d1, type, env);

      let hasMoreData = true;
      let startIndex = 0;
      let lastModStartDate = null;
      let lastModEndDate = null;

      if (lastFetchTime) {
        lastModStartDate = new Date(lastFetchTime).toISOString();
        lastModEndDate = new Date().toISOString();
      } else {
        const DaysAgo = new Date();
        DaysAgo.setDate(DaysAgo.getDate() - data_retention_days);
        lastModStartDate = DaysAgo.toISOString();
        lastModEndDate = new Date().toISOString();
      }

      while (hasMoreData) {
        let requestURL = `${url}?resultsPerPage=2000&startIndex=${startIndex}`;
        requestURL += `&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`;

        try {
          response = await fetch(requestURL, {
            headers: {
              'Accept': 'application/json',
              'apiKey': env.NVD_API_KEY,
            },
          });
        } catch (e) {
          await sendToLogQueue(env, {
            level: 'error',
            message: 'NVD API request failed',
            data: { error: e.message, requestURL }
          });
          break; // or retry logic
        }

        if (!response.ok) {
          const errorBody = await response.text();
          await sendToLogQueue(env, {
            level: 'error',
            message: 'NVD API Error',
            data: { status: response.status, body: errorBody }
          });
          break; // or retry logic
        }

        responseText = await response.text();
        const responseData = JSON.parse(responseText);

        // Log raw API response
        await sendToLogQueue(env, {
          level: 'debug',
          message: 'NVD API Raw Response',
          data: {
            url: requestURL,
            response: JSON.parse(responseText),
            startIndex,
            timestamp: new Date().toISOString()
          }
        });

        if (response.ok) {
          const responseData = JSON.parse(responseText);

          // Log pagination details
          await sendToLogQueue(env, {
            level: 'info',
            message: 'NVD API Pagination Info',
            data: {
              totalResults: responseData.totalResults,
              resultsPerPage: responseData.resultsPerPage,
              startIndex,
              remainingItems: responseData.totalResults - startIndex
            }
          });

          if (responseData?.vulnerabilities?.length > 0) {
            // Process items sequentially instead of using map
            const processedData = [];
            
            for (const item of responseData.vulnerabilities) {
              // Log raw item
              await sendToLogQueue(env, {
                level: 'debug',
                message: 'Processing Vulnerability',
                data: item
              });

              const processedItem = await processVulnerabilityItem(item);
              if (!processedItem) continue; // Skip invalid

              // Track the lastModified date for incremental fetch
              if (processedItem.lastModified && (!lastModStartDate || processedItem.lastModified > lastModStartDate)) {
                lastModStartDate = processedItem.lastModified;
              }

              // Log processed item
              await sendToLogQueue(env, {
                level: 'debug',
                message: 'Processed Vulnerability',
                data: processedItem
              });

              processedData.push(processedItem);
            }

            // Store processed data
            await storeVulnerabilitiesInD1(d1, processedData, env);

            // Update pagination
            startIndex += responseData.resultsPerPage;
            hasMoreData = startIndex < responseData.totalResults;

            // Log progress
            await sendToLogQueue(env, {
              level: 'info',
              message: 'Batch Processing Complete',
              data: {
                processed: processedData.length,
                total: responseData.totalResults,
                remaining: responseData.totalResults - startIndex
              }
            });
          } else {
            hasMoreData = false;
          }
        } else {
          throw new Error(`NVD API Error: ${response.status} ${response.statusText}`);
        }
      }

      // Update last fetch time in D1
      const fetchTime = new Date().toISOString();
      await updateLastFetchTime(d1, type, fetchTime, env);

      await sendToLogQueue(env, {
        level: 'info',
        message: `Successfully fetched NVD data from ${url}.`,
      });
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

async function getLastFetchTime(d1, source, env) {
  try {
    // Log query attempt
    await sendToLogQueue(env, {
      level: 'debug',
      message: 'Fetching last fetch time',
      data: { source }
    });

    const result = await d1.prepare(`
      SELECT last_fetch_time 
      FROM fetch_stats 
      WHERE source = ?
    `).bind(source).first();

    // Log query result
    await sendToLogQueue(env, {
      level: 'debug',
      message: 'Last fetch time result',
      data: { result }
    });

    return result?.last_fetch_time || null;
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: 'Error fetching last fetch time',
      data: {
        error: error.message,
        source,
        stack: error.stack
      }
    });
    throw error;
  }
}

async function updateLastFetchTime(d1, source, fetchTime, env, itemCount = 0) {
  try {
    await sendToLogQueue(env, {
      level: 'debug',
      message: 'Updating fetch stats',
      data: { source, fetchTime, itemCount }
    });

    await d1.prepare(`
      INSERT INTO fetch_stats (
        source,
        last_fetch_time,
        last_success_time,
        items_fetched
      ) VALUES (?, ?, ?, ?)
      ON CONFLICT(source) DO UPDATE SET
        last_fetch_time = excluded.last_fetch_time,
        last_success_time = excluded.last_success_time,
        items_fetched = fetch_stats.items_fetched + excluded.items_fetched
    `).bind(
      source,
      fetchTime,
      fetchTime,
      itemCount
    ).run();

    await sendToLogQueue(env, {
      level: 'info',
      message: 'Updated fetch stats successfully',
      data: { source, fetchTime, itemCount }
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: 'Failed to update fetch stats',
      data: {
        error: error.message,
        source,
        fetchTime,
        itemCount,
        stack: error.stack
      }
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
    if (!vulnerabilities?.length) {
      await sendToLogQueue(env, {
        level: 'warn',
        message: 'No vulnerabilities to store',
        data: { count: 0 }
      });
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
      try {
        if (!vuln.cveId) {
          await sendToLogQueue(env, {
            level: 'error',
            message: 'Invalid vulnerability data',
            data: { vuln }
          });
          continue;
        }

        await stmt.bind(
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
        ).run();

        await sendToLogQueue(env, {
          level: 'debug',
          message: `Stored vulnerability: ${vuln.cveId}`,
          data: { vuln }
        });
      } catch (error) {
        await sendToLogQueue(env, {
          level: 'error',
          message: `Failed to store vulnerability: ${vuln.cveId}`,
          data: { error: error.message, vuln }
        });
      }
    }
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: 'Error in storeVulnerabilitiesInD1',
      data: { error: error.message, stack: error.stack }
    });
    throw error;
  }
}

async function storeVulnerabilitiesInFaunaDB(vulnerabilities, env) {
  const fauna = new Client({
    secret: env.FAUNA_SECRET,
  });

  try {
    if (vulnerabilities.length === 0) {
      await sendToLogQueue(env, {
        level: 'info',
        message: 'No vulnerabilities to store in FaunaDB.',
      });
      return;
    }

    await sendToLogQueue(env, {
      level: 'info',
      message: `Storing ${vulnerabilities.length} vulnerabilities in FaunaDB.`,
    });

    for (const vuln of vulnerabilities) {
      try {
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
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error storing vulnerabilities in FaunaDB: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function processVulnerabilityItem(item) {
  if (!item?.cve?.id) {
    await sendToLogQueue(env, {
      level: 'warn',
      message: 'Skipping invalid CVE entry',
      data: { item }
    });
    return null;
  }

  const cveData = item.cve;
  const firstMetric = cveData.metrics?.cvssMetricV31?.[0]?.cvssData || {};
  return {
    cveId: cveData.id,
    link: `https://nvd.nist.gov/vuln/detail/${cveData.id}`,
    description: cveData.descriptions?.find(d => d.lang === 'en')?.value || '',
    source: cveData.sourceIdentifier || 'NVD',
    published: cveData.published || null,
    lastModified: cveData.lastModified || null,
    baseScore: firstMetric.baseScore || null,
    baseSeverity: firstMetric.baseSeverity || null,
    vectorString: firstMetric.vectorString || null,
    cwe: cveData.weaknesses?.[0]?.description?.[0]?.value || null,
    refUrls: JSON.stringify(cveData.references?.map(ref => ref.url) || []),
    fetched_at: new Date().toISOString()
  };
}