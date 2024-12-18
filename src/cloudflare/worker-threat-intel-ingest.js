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
      
      if (!isCronRequest && !isMispFetchRequest) {
        console.log("[WARN] Invalid endpoint accessed");
        return new Response("This endpoint is for fetching MISP data", { status: 404 });
      }

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

// Function to fetch threat intel data
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
    if (type === "misp") {
      let fromDateString = lastFetchTime
        ? new Date(lastFetchTime).toISOString()
        : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(); // Adjust date range as needed

      // Initialize requestBody with required parameters
      let requestBody = {
        from: fromDateString,
        limit: 50,                // Adjust limit to a smaller number if needed
        page: 1,
        returnFormat: 'json',
        metadata: true,           // Retrieve event metadata only
        // requested_attributes: ['Event.id', 'Event.info', 'Event.date'], // Optional
      };

      console.log(`Request body: ${JSON.stringify(requestBody)}`);

      // Define headers
      const headers = {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: env.MISP_API_KEY,
        "cf-worker": "true",
        "CF-Access-Client-Id": env.CF_ACCESS_CLIENT_ID,
        "CF-Access-Client-Secret": env.CF_ACCESS_SERVICE_TOKEN,
      };

      let allData = [];
      let hasMoreData = true;

      while (hasMoreData) {
        console.log(`Fetching page ${requestBody.page}`);

        await sendToLogQueue(env, {
          level: "info",
          message: `Fetching page ${requestBody.page} from MISP`,
          requestBody: { ...requestBody },
        });

        response = await fetch(url, {
          method: "POST",
          headers,
          body: JSON.stringify(requestBody),
        });

        responseText = await response.text();

        if (response.ok) {
          const responseData = JSON.parse(responseText);
          const events = responseData.response || [];
          allData = allData.concat(events);

          // Check if more data is available
          if (events.length < requestBody.limit) {
            hasMoreData = false;
          } else {
            requestBody.page += 1;
          }
        } else {
          // Log the error details
          await sendToLogQueue(env, {
            level: "error",
            message: `Failed to fetch page ${requestBody.page}`,
            status: `Response Status: ${response.status} ${response.statusText}`,
            responseBody: responseText,
          });

          throw new Error(`Failed to fetch ${type} data: ${response.status} ${response.statusText}`);
        }
      }

      data = allData;

      // Log total events fetched
      console.log(`Total events fetched: ${data.length}`);
      await sendToLogQueue(env, {
        level: "info",
        message: `Successfully fetched ${data.length} events from MISP.`,
        fetchedData: data, // Log all fetched threat intel items
      });
    }

    return data;
  } catch (error) {
    console.error(`Error fetching ${type} data: ${error.message}`);
    if (responseText) {
      console.error(`Response Body: ${responseText}`);
    }
    await sendToLogQueue(env, {
      level: "error",
      message: `Error fetching ${type} data: ${error.message}`,
      stack: error.stack,
    });

    throw error;
  }
}

// Function to filter relevant threat intel
function filterRelevantThreatIntel(stixObjects) {
  console.log("Filtering relevant threat intel");
  const relevantIndicators = [];
  
  stixObjects.forEach(object => {
    // Process Indicators
    if (object.type === "indicator" && object.pattern_type === "stix") {
      // Match IPv4 addresses
      const ipRegex = /\[ipv4-addr:value = '(.*?)'\]/;
      const matchIP = object.pattern.match(ipRegex);
      if (matchIP && matchIP[1]) {
        relevantIndicators.push({
          type: 'ip',
          value: matchIP[1],
          labels: object.labels,
          description: object.description,
          timestamp: object.modified,
          confidence: object.confidence,
        });
      }
      
      // Match IPv6 addresses
      const ipV6Regex = /\[ipv6-addr:value = '(.*?)'\]/;
      const matchIPv6 = object.pattern.match(ipV6Regex);
      if (matchIPv6 && matchIPv6[1]) {
        relevantIndicators.push({
          type: 'ip',
          value: matchIPv6[1],
          labels: object.labels,
          description: object.description,
          timestamp: object.modified,
          confidence: object.confidence,
        });
      }
    }
    
    // Extract Vulnerability Data
    if (object.type === "vulnerability") {
      const vulnerability = {
        type: 'vulnerability',
        cve: object.external_references?.find(ref => ref.source_name === 'cve')?.external_id,
        name: object.name,
        description: object.description,
        labels: object.labels,
        modified: object.modified,
      };
      relevantIndicators.push(vulnerability);
    }
    
    // Extract Software Data
    if (object.type === "software") {
      relevantIndicators.push({
        type: 'software',
        name: object.name,
        cpe: object.cpe,
        labels: object.labels,
        description: object.description,
        modified: object.modified,
      });
    }
    
    // Extract Malware and Tool Data
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