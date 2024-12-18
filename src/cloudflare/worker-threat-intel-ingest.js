import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js"; // Import custom log function

export default {
  async fetch(request, env, ctx) {
    // Early validation of required functions and environment
    if (typeof fetch !== 'function') {
      console.error("[ERROR] fetch is not available");
      return new Response("Internal Server Error", { status: 500 });
    }

    if (typeof sendToLogQueue !== 'function') {
      console.error("[ERROR] sendToLogQueue is not available");
      return new Response("Internal Server Error", { status: 500 });
    }

    try {
      // Verify environment and functions
      if (!env) {
        throw new Error('Environment not available');
      }

      console.log("[INFO] Fetch event triggered");
      
      // Verify queue availability before sending logs
      if (env.MY_QUEUE) {
        await sendToLogQueue(env, {
          level: "info",
          message: "Worker execution started",
          timestamp: new Date().toISOString()
        });
      }

      // Verify D1 binding with explicit check
      if (!env.THREAT_INTEL_DB || typeof env.THREAT_INTEL_DB.prepare !== 'function') {
        throw new Error('D1 database not properly configured');
      }
      const d1 = env.THREAT_INTEL_DB;

      // Initialize Fauna with validation
      if (!env.FAUNA_SECRET) {
        throw new Error('Fauna secret not configured');
      }

      let fauna;
      try {
        fauna = new Client({
          secret: env.FAUNA_SECRET,
        });
        if (!fauna || typeof fauna.query !== 'function') {
          throw new Error('Fauna client initialization failed');
        }
        console.log("[INFO] Fauna client initialized");
      } catch (faunaError) {
        console.error("[ERROR] Fauna initialization failed:", faunaError.message);
        throw faunaError;
      }

      // Request validation
      const url = new URL(request.url);
      const isCronRequest = ctx.scheduledTime !== undefined;
      const isMispFetchRequest = url.pathname.endsWith("/fetchmisp");

      console.log(`[INFO] Processing ${request.method} request to ${url.pathname}`);
      
      //if (!isCronRequest && !isMispFetchRequest) {
      //  console.log("[WARN] Invalid endpoint accessed");
      //  return new Response("This endpoint is for fetching MISP data", { status: 404 });
     // }

      let response;      // Declare 'response' here
      let responseText;  // Declare 'responseText' here

      try {
        await sendToLogQueue(env, {
          level: "info",
          message: "Starting threat intel fetching process.",
        });
        console.log("Starting threat intel fetching process");

        const threatIntelFeeds = [
          {
            type: "misp",
            url: "https://simp.xsight.network/events/restSearch",
            format: "misp",
          },
          // Add more feeds if needed
        ];

        let allThreatIntel = [];

        for (const feed of threatIntelFeeds) {
          console.log(`Fetching data from feed: ${feed.url}`);
          const feedData = await fetchThreatIntelData(feed.url, feed.type, env, feed.format);
          console.log(`Fetched ${feedData.length} items from feed: ${feed.url}`);
          allThreatIntel = [...allThreatIntel, ...feedData];
        }

        console.log(`Total threat intel items fetched: ${allThreatIntel.length}`);

        // Log the total threat intel items fetched to Elastic
        await sendToLogQueue(env, {
          level: "info",
          message: `Total threat intel items fetched: ${allThreatIntel.length}`,
        });

        // Function to send data in batches
        async function sendDataInBatches(env, dataArray, batchSizeInBytes = 120000) {
          let currentBatch = [];
          let currentBatchSize = 0;

          for (const item of dataArray) {
            const itemString = JSON.stringify(item);
            const itemSize = new TextEncoder().encode(itemString).length;

            // If adding this item exceeds the batch size limit, send the current batch
            if (currentBatchSize + itemSize > batchSizeInBytes) {
              await sendToLogQueue(env, {
                level: "info",
                message: `Threat intel items batch`,
                data: currentBatch,
              });

              // Reset the batch
              currentBatch = [];
              currentBatchSize = 0;
            }

            // Add the item to the current batch
            currentBatch.push(item);
            currentBatchSize += itemSize;
          }

          // Send any remaining items in the last batch
          if (currentBatch.length > 0) {
            await sendToLogQueue(env, {
              level: "info",
              message: `Threat intel items batch`,
              data: currentBatch,
            });
          }
        }

        // Use the function to send all threat intel items
        await sendDataInBatches(env, allThreatIntel);

        const relevantIndicators = filterRelevantThreatIntel(allThreatIntel);
        console.log(`Relevant indicators extracted: ${relevantIndicators.length}`);

        // Store data in D1 and FaunaDB
        await storeInD1(d1, relevantIndicators, env);
        console.log("Data stored in D1 successfully");

        await storeInFaunaDB(relevantIndicators, fauna, env);
        console.log("Data stored in FaunaDB successfully");

        await sendToLogQueue(env, {
          level: "info",
          message: "Threat intel data ingestion finished successfully.",
        });
        console.log("Threat intel data ingestion finished successfully");

        return new Response("Threat intel data ingestion finished successfully.", { status: 200 });
      } catch (error) {
        console.error(`Error: ${error.message}`);
        if (responseText) {
          console.error(`Response Body: ${responseText}`);
        }
        await sendToLogQueue(env, {
          level: "error",
          message: `Error fetching/processing threat intel data: ${error.message}`,
          stack: error.stack,
        });
        return new Response(`Error fetching/processing threat intel data: ${error.message}`, { status: 500 });
      }
    } catch (error) {
      console.error("[ERROR] Worker execution failed:", error.message);
      
      // Safe logging with queue check
      if (env?.MY_QUEUE) {
        await sendToLogQueue(env, {
          level: "error",
          message: `Worker execution failed: ${error.message}`,
          stack: error.stack,
          timestamp: new Date().toISOString()
        });
      }
      
      return new Response(JSON.stringify({
        error: "Internal Server Error",
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
};


//Function to fetch
async function fetchThreatIntelData(url, type, env, format, lastFetchTime) {
  let response;
  let responseText;

  try {
    console.log(`Fetching ${type} data from ${url}`);
      await sendToLogQueue(env, {
        level: "info",
        message: `Fetching ${type} data from ${url}.`,
      });

      let data = [];
      let allData = [];
  if (type === "misp") {
      let requestBody = {
         limit: 50,
          page: 1,
          type: ["ip-src", "ip-dst", "vulnerability", "malware", "tool"],
          tags: ["severity:critical", "severity:high"],
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

        while (hasMoreData) {
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
                'Authorization': env.MISP_API_KEY , // Set the api key in authorization header,
                "cf-worker": "true",
                "CF-Access-Client-Id": env.CF_ACCESS_CLIENT_ID,
                "CF-Access-Client-Secret": env.CF_ACCESS_SERVICE_TOKEN,
                },
                body: JSON.stringify(requestBody)
          });
              responseText = await response.text();

               if (response.ok) {
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
                         hasMoreData = false;
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
        data= allData;
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
function filterRelevantThreatIntel(events) {
  console.log("Filtering relevant threat intel");
  const relevantIndicators = [];

  events.forEach(event => {
    // Process each attribute in the event
    if (event.Attribute && Array.isArray(event.Attribute)) {
      event.Attribute.forEach(attribute => {
        // Check if the attribute type matches
        if (["ip-src", "ip-dst"].includes(attribute.type)) {
          relevantIndicators.push({
            type: 'ip',
            value: attribute.value,
            category: attribute.category,
            comment: attribute.comment,
            timestamp: attribute.timestamp,
            tags: attribute.Tag ? attribute.Tag.map(tag => tag.name) : [],
          });
        } else if (attribute.type === "vulnerability") {
          relevantIndicators.push({
            type: 'vulnerability',
            cve: attribute.value,
            category: attribute.category,
            comment: attribute.comment,
            timestamp: attribute.timestamp,
            tags: attribute.Tag ? attribute.Tag.map(tag => tag.name) : [],
          });
        } else if (attribute.type === "malware") {
          relevantIndicators.push({
            type: 'malware',
            name: attribute.value,
            category: attribute.category,
            comment: attribute.comment,
            timestamp: attribute.timestamp,
            tags: attribute.Tag ? attribute.Tag.map(tag => tag.name) : [],
          });
        } else if (attribute.type === "tool") {
          relevantIndicators.push({
            type: 'tool',
            name: attribute.value,
            category: attribute.category,
            comment: attribute.comment,
            timestamp: attribute.timestamp,
            tags: attribute.Tag ? attribute.Tag.map(tag => tag.name) : [],
          });
        }
      });
    }
  });

  console.log(`Filtered ${relevantIndicators.length} relevant indicators`);
  return relevantIndicators;
}

// Function to store data in D1
async function storeInD1(d1, data, env) {
  try {
    console.log("Storing data in D1");
    for (const threat of data) {
      const searchableText = `${threat.type} ${threat.value || ''} ${threat.description || ''}`;
      await d1
        .prepare(
          'INSERT INTO threat_intel (type, value, category, timestamp, comment, searchable_text) VALUES (?, ?, ?, ?, ?, ?)',
        )
        .bind(
          threat.type,
          threat.value || null,
          threat.category || null,
          threat.timestamp || null,
          threat.comment || null,
          searchableText,
        )
        .run();
    }
    console.log("Data stored in D1 successfully");
    await sendToLogQueue(env, {
      level: "info",
      message: "Threat intel data stored in D1 successfully.",
    });
  } catch (error) {
    console.error(`Error storing data in D1: ${error.message}`);
    await sendToLogQueue(env, {
      level: "error",
      message: `Error storing threat intel in D1: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}



// Function to store data in FaunaDB
async function storeInFaunaDB(data, fauna, env) {
  try {
    console.log("Storing data in FaunaDB");
    for (const threat of data) {
      const query = fql`
        Threats.create({
          data: ${threat}
        })
      `;
      await fauna.query(query);
    }
    console.log("Data stored in FaunaDB successfully");
    await sendToLogQueue(env, {
      level: "info",
      message: "Threat intel data stored in FaunaDB successfully.",
    });
  } catch (error) {
    console.error(`Error storing data in FaunaDB: ${error.message}`);
    await sendToLogQueue(env, {
      level: "error",
      message: `Error storing threat intel in FaunaDB: ${error.message}`,
      stack: error.stack,
    });
    throw error;
  }
}