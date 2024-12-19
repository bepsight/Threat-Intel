import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js"; // Import custom log function

export default {
  async fetch(request, env, ctx) {
    const d1 = env.MY_D1; // Get D1 binding from environment
    const fauna = new Client({
      secret: env.FAUNA_SECRET, // Get Fauna secret from environment
    });

    // 1. Check if this request is triggered by a cron schedule, or it is for the /fetchmisp endpoint
    const isCronRequest = ctx.scheduledTime !== undefined; // Detect if the request is scheduled
    const isMispFetchRequest = request.url.endsWith("/fetchmisp");

    // if this request is not related to fetching misp data, return
    if (!isCronRequest && !isMispFetchRequest) {
      return new Response("This endpoint is for fetching MISP data", {
        status: 404,
      });
    }
    try {
      // Log that the fetching process has started using the custom log function
      await sendToLogQueue(env, {
        level: "info",
        message: "Starting threat intel fetching process.",
      });

      // Define the different feeds that you want to fetch, can be MISP or other sources.
      const threatIntelFeeds = [
          //{
          //  type: "misp",
          //  url: "https://simp.xsight.network/events/restSearch",
          //  format: "misp",
          //},
           {
            type: "nvd",
            url: "https://services.nvd.nist.gov/rest/json/cves/2.0",
            format: "nvd",
          },
          {
            type: "rss",
            url: "https://api.rss.app/v1/feeds", // Using feeds to access list of feeds in rss app.
            format: "rss",
          }
      ];

      let allThreatIntel = [];
      for (const feed of threatIntelFeeds) {
          console.log(`Fetching data from feed ${feed.type}: ${feed.url}`);
        const feedData = await fetchThreatIntelData(
          feed.url,
          feed.type,
          env,
          feed.format
        );
          console.log(`Fetched ${feedData.length} items from feed ${feed.type}: ${feed.url}`);
        allThreatIntel = [...allThreatIntel, ...feedData];
      }
          console.log(`Total threat intel items fetched: ${allThreatIntel.length}`);

      // Log the total threat intel items fetched to Elastic
      await sendToLogQueue(env, {
        level: "info",
        message: `Total threat intel items fetched: ${allThreatIntel.length}`,
      });

      if (type === "stix") {
        const relevantIndicators = filterRelevantThreatIntel(allThreatIntel);
        console.log(`Relevant indicators extracted: ${relevantIndicators.length}`);
        // Proceed with relevantIndicators
        // e.g., store in database
        await storeInD1(env.DB, relevantIndicators, env);
        await storeInFaunaDB(relevantIndicators, env.FAUNA_SECRET, env);
      } else {
        // For other feed types, use allThreatIntel as is
        console.log(`Processing ${allThreatIntel.length} items from ${type} feed`);
        // Proceed with allThreatIntel data
        await storeInD1(env.DB, allThreatIntel, env);
        await storeInFaunaDB(allThreatIntel, env.FAUNA_SECRET, env);
      }

      await sendToLogQueue(env, {
        level: "info",
        message: "Threat intel data ingestion finished successfully.",
      });
      console.log("Threat intel data ingestion finished successfully");

      return new Response("Threat intel data ingestion finished successfully.", {
        status: 200,
      });
    } catch (error) {
      // Send error log using custom logging function
      await sendToLogQueue(env, {
        level: "error",
        message: `Error fetching/processing threat intel data: ${error.message}`,
        stack: error.stack, // Send the stack trace for better debugging
      });
      // Return an error response with the error message
      return new Response(
        `Error fetching/processing threat intel data: ${error.message}`,
        { status: 500 }
      );
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
     ///////////////////////////
     // Process MISP DATA
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

      ///////////////////////////
      // Process NVD DATA
       if (type === "nvd") {
      let hasMoreData = true;
           let startIndex= 0;
          let lastModStartDate= null;
          let lastModEndDate= null;
        if(lastFetchTime){
          const lastFetchDate = new Date(lastFetchTime)
            lastModStartDate= lastFetchDate.toISOString()
            lastModEndDate = new Date().toISOString()

         } else {
            const thirtyDaysAgo = new Date();
           thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
             lastModStartDate = thirtyDaysAgo.toISOString();
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
            response= await fetch(requestURL, {
              headers: {
                 'Accept': 'application/json',
                'apiKey': env.NVD_API_KEY //API key from environment variables (I am using for test purposes)
                 },
              })
               responseText = await response.text();
            if(response.ok){
               const responseData = JSON.parse(responseText);
                 if (responseData && responseData.vulnerabilities) {
                   allData=  [...allData, ...responseData.vulnerabilities];
                     startIndex= startIndex+ responseData.resultsPerPage
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
         data= allData;
      }

    ///////////////////////////
    // Process RSS DATA
     if (type === "rss") {
          let requestURL= `${url}?limit=100`
          // Log the URL that will be used for data fetch.
            await sendToLogQueue(env, {
                level: "info",
                 message: `Fetching ${type} data from ${requestURL}.`,
            });

         response= await fetch(requestURL, {
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

        ///////////////////////////
        // Process STIX DATA
        if (type === "stix") {
          if(lastFetchTime){
            const response = await fetch(`${url}?modified_since=${lastFetchTime}`);
             if (!response.ok) {
               throw new Error(
                `Failed to fetch ${type} data: ${response.status} ${response.statusText}`
              );
             }
             const responseData = await response.json();
             allData = responseData.objects;
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
            allData = responseData.objects;
         }
        data = allData;
      }


        // Log that the fetching process has been finished successfully
        await sendToLogQueue(env, {
            level: "info",
            message: `Successfully fetched ${type} data from ${url}.`,
        });
        // Return data
       return data;
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

async function getLastFetchTime(d1, sourceUrl, env) {
  try {
    const { results } = await d1
      .prepare("SELECT last_fetch_time FROM tracker WHERE id = ?")
      .bind(sourceUrl)
      .all();

    if (results && results.length > 0 && results[0].last_fetch_time) {
        await sendToLogQueue(env, {
           level: "info",
            message: `Last fetch time found for source: ${sourceUrl}. Time: ${results[0].last_fetch_time}.`,
          });
         return results[0].last_fetch_time;
    }

    await sendToLogQueue(env, {
        level: "info",
        message: `Last fetch time not found for source: ${sourceUrl}. Returning null.`,
      });
    return null; // Return null if no previous fetch time is available.
  } catch (error) {
     await sendToLogQueue(env, {
        level: "error",
        message: `Error getting last fetch time from D1 for source: ${sourceUrl}. ${error.message}`,
         stack: error.stack,
      });
    throw error;
  }
}

async function updateLastFetchTime(d1, sourceUrl, fetchTime, env) {
    try {
         await d1
          .prepare(
            "INSERT OR REPLACE INTO tracker (id, last_fetch_time) VALUES (?, ?)"
          )
          .bind(sourceUrl, fetchTime)
           .run();
           await sendToLogQueue(env, {
            level: "info",
            message: `Last fetch time updated in D1 for source: ${sourceUrl}. Time: ${fetchTime}.`,
        });
    } catch (error) {
        await sendToLogQueue(env, {
            level: "error",
            message: `Error updating last fetch time in D1 for source: ${sourceUrl}. ${error.message}`,
            stack: error.stack,
        });
       throw error;
    }
}