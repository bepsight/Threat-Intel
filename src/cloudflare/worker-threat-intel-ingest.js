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

async function fetchThreatIntelData(url, type, env, format, lastFetchTime) {
  let response;
  let responseText;

  try {
      // Log the data fetching process
        await sendToLogQueue(env, {
            level: "info",
            message: `Fetching ${type} data from ${url}.`,
        });

    let allData = [];

   if (type === "misp") {
       // Same MISP logic as before
         let requestBody = {
           limit: 50,
            page: 1,
           includeAttributes: true,
            includeContext: true,
            returnFormat: "json"
        };
         //Use time based filters if they are available to fetch only new data
           if(lastFetchTime){
            const fromDate = new Date(lastFetchTime);
            const fromDateString= fromDate.toISOString();
             requestBody.from = fromDateString;
          }
          else {
            const thirtyDaysAgo = new Date();
             thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            const thirtyDaysAgoString = thirtyDaysAgo.toISOString();
             requestBody.from = thirtyDaysAgoString;
          }

          // Log the filter parameters that will be used for data fetch
           await sendToLogQueue(env, {
               level: "info",
               message: `Using filters ${JSON.stringify(requestBody)} to fetch ${type} data from ${url}.`,
             });
            let hasMoreData = true;
           while(hasMoreData){
              console.log(`Fetching page ${requestBody.page}`);
              await sendToLogQueue(env, {
                level: "info",
                  message: `Fetching page ${requestBody.page} from MISP`,
                 requestBody: { ...requestBody },
              });
             response = await fetch(url, {
               method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                     'Authorization': env.MISP_API_KEY, // Set the api key in authorization header
                      "cf-worker": "true",
                      "CF-Access-Client-Id": env.CF_ACCESS_CLIENT_ID,
                      "CF-Access-Client-Secret": env.CF_ACCESS_SERVICE_TOKEN,

                 },
                 body: JSON.stringify(requestBody)
              });
                responseText = await response.text();

                if(response.ok){
                  const responseData = JSON.parse(responseText);
                    if (responseData && responseData.response) {
                       if (Array.isArray(responseData.response)) {
                            for( const event of responseData.response){
                             allData.push(event);
                            }

                       }
                       else {
                            allData.push(responseData.response);
                       }
                        if (responseData.response.length < requestBody.limit ) {
                             hasMoreData= false;
                         } else {
                            requestBody.page += 1;
                        }
                     }
                   else {
                          hasMoreData = false;
                      }

                 }
                else {
                    await sendToLogQueue(env, {
                        level: "error",
                         message: `Failed to fetch ${type} data: ${response.status} ${response.statusText}`,
                         responseBody: responseText,
                    });
                     throw new Error(
                       `Failed to fetch ${type} data: ${response.status} ${response.statusText}`
                       );
                }
           }
           data = allData;
       }
       if (type === "nvd") {
          let hasMoreData = true;
           let startIndex= 0;
          let lastModStartDate= null;
          let lastModEndDate= null;
         if(lastFetchTime){
           const lastFetchDate = new Date(lastFetchTime)
             lastModStartDate= lastFetchDate.toISOString()
             lastModEndDate = new Date().toISOString()

           }
           else {
              const thirtyDaysAgo = new Date();
              thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
              lastModStartDate= thirtyDaysAgo.toISOString();
              lastModEndDate= new Date().toISOString()
            }

          while(hasMoreData){
               let requestURL= `${url}?resultsPerPage=2000&startIndex=${startIndex}`
               if(lastModStartDate && lastModEndDate){
                 requestURL= `${requestURL}&lastModStartDate=${lastModStartDate}&lastModEndDate=${lastModEndDate}`
               }
            // Log the URL that will be used for data fetch.
              await sendToLogQueue(env, {
                  level: "info",
                  message: `Fetching ${type} data from ${requestURL}.`,
              });
              response = await fetch(requestURL, {
                headers: {
                  'Accept': 'application/json',
                   'apiKey': env.NVD_API_KEY //API key from environment variables (I am using for test purposes)
                 },
              });
                responseText = await response.text();
              if(response.ok){
                 const responseData = JSON.parse(responseText);
                 if (responseData && responseData.vulnerabilities) {
                   allData= [...allData, ...responseData.vulnerabilities];
                    startIndex = startIndex+ responseData.resultsPerPage;
                  if (startIndex >= responseData.totalResults) {
                       hasMoreData = false;
                    }
                 }
                 else {
                       hasMoreData= false;
                 }
              }
                else {
                    await sendToLogQueue(env, {
                        level: "error",
                        message: `Failed to fetch ${type} data: ${response.status} ${response.statusText}`,
                        responseBody: responseText,
                     });
                      throw new Error(
                        `Failed to fetch ${type} data: ${response.status} ${response.statusText}`
                     );
               }
          }
        data = allData;
        }

     if (type === "rss") {
          let requestURL= `${url}?limit=100`
          // Log the URL that will be used for data fetch.
          await sendToLogQueue(env, {
              level: "info",
                message: `Fetching ${type} data from ${requestURL}.`,
          });
        response = await fetch(requestURL, {
             method: 'GET',
               headers: {
                   'Accept': 'application/json',
                      'Authorization': `Bearer ${env.RSS_API_KEY}:${env.RSS_API_SECRET}`
                    }
              })
          if(response.ok){
             const responseData = await response.json();
              if(responseData && responseData.data && Array.isArray(responseData.data)){
                for(const feed of responseData.data){
                  if(feed && feed.items && Array.isArray(feed.items)){
                    allData= [...allData, ...feed.items];
                    }
                 }
               }
             } else {
                  await sendToLogQueue(env, {
                      level: "error",
                      message: `Failed to fetch ${type} data: ${response.status} ${response.statusText}`,
                      responseBody: responseText,
                 });
                 throw new Error(
                      `Failed to fetch ${type} data: ${response.status} ${response.statusText}`
                   );
             }
          data = allData;
        }

     if (type === "stix") {
       if(lastFetchTime){
            const response = await fetch(`${url}?modified_since=${lastFetchTime}`);
             if (!response.ok) {
               throw new Error(
                `Failed to fetch ${type} data: ${response.status} ${response.statusText}`
               );
             }
             const responseData = await response.json();
             data = responseData.objects;
           }
          else{
             const thirtyDaysAgo = new Date();
             thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            const thirtyDaysAgoString = thirtyDaysAgo.toISOString();
             const response = await fetch(`${url}?modified_since=${thirtyDaysAgoString}`);
             if (!response.ok) {
              throw new Error(
                `Failed to fetch ${type} data: ${response.status} ${response.statusText}`
               );
            }
              const responseData = await response.json();
           data = responseData.objects;
         }
       }

         // Log that the fetching process has been finished successfully
        await sendToLogQueue(env, {
            level: "info",
            message: `Successfully fetched ${type} data from ${url}.`,
        });
        // Return data
      return allData;
  } catch (error) {
        // Log error using the custom logging function
          if (responseText) {
              console.error(`Response Body: ${responseText}`);
           }
         await sendToLogQueue(env, {
            level: "error",
            message: `Error fetching ${type} data: ${error.message}`,
            stack: error.stack, // Send the stack trace for better debugging
        });

         throw error; // Re-throw the error so it will be handled outside of this function.
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
    }
    else if (type === 'nvd') {
          processedData = data.map((item) => {
        if (!item.cve) {
         return null
        }
      const cveItem= item.cve;
        return {
            cve_id: cveItem.id,
            source_identifier: cveItem.sourceIdentifier || null,
            published: cveItem.published || null,
            last_modified: cveItem.lastModified || null,
            description:
              cveItem.descriptions && cveItem.descriptions.length > 0
               ? cveItem.descriptions[0].value
               : null,
            base_score: cveItem.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || cveItem.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore || null,
            base_severity: cveItem.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || cveItem.metrics?.cvssMetricV2?.[0]?.baseSeverity || null,
            vector_string: cveItem.metrics?.cvssMetricV31?.[0]?.cvssData?.vectorString || cveItem.metrics?.cvssMetricV2?.[0]?.vectorString || null,
            cwe: cveItem.weaknesses?.[0]?.description?.[0]?.value || null,
            ref_urls: JSON.stringify(item.references?.map(ref => ref.url) || [])
         }
          }).filter(vuln=> vuln != null);
      console.log(`Processed ${processedData.length} vulnerabilities from NVD feed.`);
    } else if (type === 'rss') {
      // For RSS data, process as needed
         processedData = data;
       console.log(`Processed ${data.length} items from RSS feed.`);
    }
    else {
      throw new Error(`Unsupported feed type: ${type}`);
    }


      // Store processed data in D1 and FaunaDB
      if (processedData.length > 0) {
            if (type === 'nvd') {
                 await storeVulnerabilitiesInD1(d1, processedData, env);
              await storeVulnerabilitiesInFaunaDB(processedData, env);
               }
            else {
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
          level: "info",
          message: `Successfully processed and stored data from ${type} feed.`,
       });
   } catch (error) {
      await sendToLogQueue(env, {
          level: "error",
          message: `Error processing data from ${type} feed: ${error.message}`,
          stack: error.stack,
     });
       throw error;
   }
}

async function storeVulnerabilitiesInD1(d1, vulnerabilities, env) {
  try {
    await sendToLogQueue(env, {
      level: 'info',
      message: `Starting to store ${vulnerabilities.length} vulnerabilities in D1`
    });

    const stmt = d1.prepare(`
      INSERT INTO vulnerabilities (
        cve_id, source_identifier, published, last_modified, 
        description, base_score, base_severity, vector_string, 
        cwe, ref_urls
      ) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(cve_id) DO UPDATE SET
        last_modified = excluded.last_modified,
        description = excluded.description,
        base_score = excluded.base_score,
        base_severity = excluded.base_severity,
        vector_string = excluded.vector_string,
        cwe = excluded.cwe,
        ref_urls = excluded.ref_urls
    `);

    for (const vuln of vulnerabilities) {
      try {
         await stmt.bind(
              vuln.cve_id || null,
              vuln.source_identifier || null,
              vuln.published || null,
              vuln.last_modified || null,
              vuln.description || null,
              vuln.base_score || null,
              vuln.base_severity || null,
              vuln.vector_string || null,
              vuln.cwe || null,
              vuln.ref_urls || null
            ).run();

        await sendToLogQueue(env, {
          level: 'debug',
          message: `Stored vulnerability ${vuln.cve_id}`,
          data: {
            cve_id: vuln.cve_id,
            source: vuln.source_identifier,
          },
        });
      } catch (error) {
         await sendToLogQueue(env, {
          level: 'error',
          message: `Failed to store vulnerability`,
          error: error.message,
            data: vuln
        });
       }
    }

    await sendToLogQueue(env, {
      level: 'info',
      message: `Completed storing vulnerabilities in D1`,
      data: {
        total_processed: vulnerabilities.length
      }
    });
  } catch (error) {
    await sendToLogQueue(env, {
      level: 'error',
      message: 'Failed to prepare D1 statement',
      error: error.message
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