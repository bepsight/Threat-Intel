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
      lastFetchTime = await getLastFetchTime(d1, type, env);

      // Log fetch initiation
      await sendToLogQueue(env, {
        level: 'info',
        message: 'Starting NVD fetch',
        data: {
          lastFetchTime,
          retention_days: data_retention_days
        }
      });

      let hasMoreData = true;
      let startIndex = 0;
      let totalItems = 0;
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

      // First request to get total count
      let requestURL = `${url}?resultsPerPage=2000&startIndex=0`;
      requestURL += `&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`;

      response = await fetch(requestURL, {
        headers: {
          'Accept': 'application/json',
          'apiKey': env.NVD_API_KEY,
        },
      });

      if (response.ok) {
        const initialData = await response.json();
        totalItems = initialData.totalResults;

        // Log total items to be fetched
        await sendToLogQueue(env, {
          level: 'info',
          message: 'NVD fetch statistics',
          data: {
            total_items: totalItems,
            start_date: lastModStartDate,
            end_date: lastModEndDate,
            pages: Math.ceil(totalItems / 2000)
          }
        });
      }

      // Continue with existing pagination logic...
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

              const processedItem = processVulnerabilityItem(item);
              processedData.push(processedItem);
            }

            // Store processed data
            await storeVulnerabilitiesInD1(d1, processedData, env);
            await updateLastFetchTime(d1, type, new Date().toISOString(), env, processedData.length, true);

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

            // Add progress logging
            await sendToLogQueue(env, {
              level: 'info',
              message: 'NVD fetch progress',
              data: {
                processed: startIndex,
                total: totalItems,
                remaining: totalItems - startIndex,
                progress_percentage: ((startIndex / totalItems) * 100).toFixed(2)
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

async function getLastFetchTime(d1, source, env) {
  try {
    const result = await d1.prepare(`
      SELECT last_fetch_time FROM fetch_stats WHERE source = ?
    `).bind(source).first();

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

async function updateLastFetchTime(d1, source, fetchTime, env, itemCount = 0, success = true) {
  try {
    await d1.prepare(`
      INSERT INTO fetch_stats (source, last_fetch_time, last_success_time, items_fetched)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(source) DO UPDATE SET
        last_fetch_time = excluded.last_fetch_time,
        last_success_time = CASE 
          WHEN ? THEN excluded.last_fetch_time 
          ELSE fetch_stats.last_success_time 
        END,
        items_fetched = items_fetched + ?
    `).bind(
      source, 
      fetchTime, 
      success ? fetchTime : null,
      itemCount,
      success ? 1 : 0,
      itemCount
    ).run();

    await sendToLogQueue(env, {
      level: 'info',
      message: `Updated fetch stats for ${source}: time=${fetchTime}, success=${success}, items=${itemCount}`,
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: `Error updating fetch stats: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}

async function processVulnerabilityItem(item) {
  // From the logs we can see the correct data structure
  const cveData = item.cve;
  
  return {
    cveId: cveData.id,
    link: `https://nvd.nist.gov/vuln/detail/${cveData.id}`,
    description: cveData.descriptions?.find(d => d.lang === 'en')?.value || '',
    source: cveData.sourceIdentifier,
    published: cveData.published,
    lastModified: cveData.lastModified,
    metrics: cveData.metrics,
    weaknesses: cveData.weaknesses,
    references: cveData.references,
    fetched_at: new Date().toISOString()
  };
}