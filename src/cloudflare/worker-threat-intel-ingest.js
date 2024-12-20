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
  let data_retention_days = 5;

  try {
    let url = '';
    let lastFetchTime = null;
    let allData = [];

    if (type === 'nvd') {
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
        const DaysAgo = new Date();
        DaysAgo.setDate(DaysAgo.getDate() - data_retention_days);
        lastModStartDate = DaysAgo.toISOString();
        lastModEndDate = new Date().toISOString();
      }

      while (hasMoreData) {
        let requestURL = `${url}?resultsPerPage=2000&startIndex=${startIndex}`;
        requestURL += `&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`;

        // Log request
        await sendToLogQueue(env, {
          level: 'info',
          message: 'NVD API Request',
          data: { url: requestURL }
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

          // Log raw response
          await sendToLogQueue(env, {
            level: 'debug',
            message: 'NVD Raw Response',
            data: responseData
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

              const processedItem = {
                cveId: item.id || 'Unknown',
                link: `https://nvd.nist.gov/vuln/detail/${item.id || 'Unknown'}`,
                description: item.descriptions?.[0]?.value || '',
                source: item.sourceIdentifier || 'NVD',
                published: item.published || new Date().toISOString(),
                lastModified: item.lastModified || new Date().toISOString(),
                metrics: item.metrics || null,
                weaknesses: item.weaknesses || null,
                references: item.references || null,
                fetched_at: new Date().toISOString()
              };

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
      await updateLastFetchTime(d1, url, fetchTime, env);

      await sendToLogQueue(env, {
        level: 'info',
        message: `Successfully fetched NVD data from ${url}.`,
      });
    } else if (type === 'rss') {
      // ...existing RSS handling code...
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

async function getLastFetchTime(d1, url, env) {
  try {
    const result = await d1.prepare(`
      SELECT last_fetch_time FROM fetch_times WHERE url = ?
    `).bind(url).first();

    if (result) {
      return result.last_fetch_time;
    } else {
      return null;
    }
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error getting last fetch time: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function storeVulnerabilitiesInD1(d1, vulnerabilities, env) {
  try {
    if (vulnerabilities.length === 0) {
      await sendToLogQueue(env, {
        level: 'info',
        message: 'No vulnerabilities to store in D1.',
      });
      return;
    }

    await sendToLogQueue(env, {
      level: 'info',
      message: `Storing ${vulnerabilities.length} vulnerabilities in D1.`,
    });

    const stmt = d1.prepare(`
      INSERT INTO vulnerabilities (
        cve_id, link, description, source_identifier,
        published, last_modified, base_score, base_severity,
        vector_string, cwe, ref_urls, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(cve_id) DO UPDATE SET
        link = excluded.link,
        description = excluded.description,
        source_identifier = excluded.source_identifier,
        published = excluded.published,
        last_modified = excluded.last_modified,
        base_score = excluded.base_score,
        base_severity = excluded.base_severity,
        vector_string = excluded.vector_string,
        cwe = excluded.cwe,
        ref_urls = excluded.ref_urls,
        created_at = excluded.created_at
    `);

    for (const vuln of vulnerabilities) {
      try {
        // Extract CVSS metrics if available
        const baseScore = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || null;
        const baseSeverity = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || null;
        const vectorString = vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.vectorString || null;
        // Extract CWE if available
        const cwe = vuln.weaknesses?.[0]?.description?.[0]?.value || null;
        // Extract reference URLs
        const refUrls = JSON.stringify(vuln.references?.map(ref => ref.url) || []);

        await stmt.bind(
          vuln.cveId,
          vuln.link,
          vuln.description,
          vuln.source,
          vuln.published,
          vuln.lastModified,
          baseScore,
          baseSeverity,
          vectorString,
          cwe,
          refUrls,
          vuln.fetched_at
        ).run();

        await sendToLogQueue(env, {
          level: 'debug',
          message: `Stored vulnerability: ${vuln.cveId}`,
        });
      } catch (error) {
        await sendToLogQueue(env, {
          level: 'error',
          message: `Failed to store vulnerability: ${vuln.cveId}`,
          error: error.message,
        });
      }
    }

    await sendToLogQueue(env, {
      level: 'info',
      message: 'Vulnerabilities stored in D1 successfully.',
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error storing vulnerabilities in D1: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function updateLastFetchTime(d1, url, fetchTime, env) {
  try {
    await d1.prepare(`
      INSERT INTO fetch_times (url, last_fetch_time)
      VALUES (?, ?)
      ON CONFLICT(url) DO UPDATE SET
        last_fetch_time = excluded.last_fetch_time
    `).bind(url, fetchTime).run();

    await sendToLogQueue(env, {
      level: 'info',
      message: `Updated last fetch time for ${url} to ${fetchTime}.`,
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error updating last fetch time: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}