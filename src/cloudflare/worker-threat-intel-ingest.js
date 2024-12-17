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
  let headers;
  
  try {
    console.log(`Fetching ${type} data from ${url}`);
    await sendToLogQueue(env, {
      level: "info",
      message: `Fetching ${type} data from ${url}.`,
    });

    let data = [];
    if (type === "misp") {
      let requestBody = {};
      if (lastFetchTime) {
        const fromDateString = new Date(lastFetchTime).toISOString();
        requestBody = { from: fromDateString };
      } else {
        const thirtyDaysAgoString = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
        requestBody = { from: thirtyDaysAgoString };
      }

      console.log(`Request body: ${JSON.stringify(requestBody)}`);

      // Define headers before use
      headers = {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: env.MISP_API_KEY,
        "cf-worker": "true"
      };

      // Log request details
      await sendToLogQueue(env, {
        level: "info",
        message: "Request details",
        headers: JSON.stringify(headers),
        body: JSON.stringify(requestBody),
        url: url
      });

      response = await fetch(url, {
        method: "POST",
        headers,
        body: JSON.stringify(requestBody),
      });

      responseText = await response.text();
      console.log(`Response Status: ${response.status} ${response.statusText}`);
      //console.log(`Response Body: ${responseText}`);

      await sendToLogQueue(env, {
        level: "info",
        message: `Received Response from ${type} endpoint ${url} `,
        status: `Response Status: ${response.status} ${response.statusText}`,
        responseBody: `Response Body: ${responseText}`,
      });


      if (response.ok) {
        const responseData = JSON.parse(responseText);
        data = responseData.response.Event || [];
      } else {
        throw new Error(`Failed to fetch ${type} data: ${response.status} ${response.statusText}`);
      }
    }

    console.log(`Successfully fetched ${data.length} ${type} items from ${url}`);

    // Log successful fetch
    await sendToLogQueue(env, {
      level: "info",
      message: `Successfully fetched ${type} data from ${url}.`,
    });
    return data;
  } catch (error) {
    console.error(`Error fetching ${type} data: ${error.message}`);
    if (responseText) {
      console.error(`Response Body: ${responseText}`);
    }
    // Log error
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
  stixObjects.forEach((object) => {
    // Process MISP events
    if (object && object.Attribute) {
      object.Attribute.forEach((attr) => {
        relevantIndicators.push({
          type: attr.type,
          value: attr.value,
          category: attr.category,
          timestamp: attr.timestamp,
          comment: attr.comment,
        });
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