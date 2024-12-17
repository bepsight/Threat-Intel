import { Client, fql } from "fauna";
import { sendToLogQueue } from "../utils/log.js"; // Import custom log function

export default {
  async fetch(request, env, ctx) {
    const requestId = crypto.randomUUID();

    try {
      console.log(`[${requestId}] Fetch event triggered`);
      await sendToLogQueue(env, {
        level: "info",
        requestId,
        message: "Fetch event triggered",
      });

      // Initialize clients and check request
      const d1 = env.THREAT_INTEL_DB;
      const fauna = new Client({ secret: env.FAUNA_SECRET });

      console.log(`[${requestId}] Fauna client initialized`);
      await sendToLogQueue(env, {
        level: "info",
        requestId,
        message: "Fauna client initialized",
      });

      const url = new URL(request.url);
      const isCronRequest = ctx.scheduledTime !== undefined;
      const isMispFetchRequest = url.pathname.endsWith("/fetchmisp");

      console.log(
        `[${requestId}] Request type: ${isCronRequest ? "CRON" : "HTTP"}, Endpoint: ${
          url.pathname
        }`
      );
      await sendToLogQueue(env, {
        level: "info",
        requestId,
        message: `Request validation - CRON: ${isCronRequest}, MISP: ${isMispFetchRequest}`,
      });

      if (!isCronRequest && !isMispFetchRequest) {
        console.log(`[${requestId}] Invalid endpoint accessed: ${url.pathname}`);
        await sendToLogQueue(env, {
          level: "warn",
          requestId,
          message: `Invalid endpoint accessed: ${url.pathname}`,
        });
        return new Response("Invalid endpoint", { status: 404 });
      }

      // Fetch and process threat intel
      const threatIntelFeeds = [
        {
          type: "misp",
          url: "https://simp.xsight.network/events/restSearch",
          format: "misp",
        },
      ];

      console.log(
        `[${requestId}] Starting threat intel fetch for ${threatIntelFeeds.length} feeds`
      );
      await sendToLogQueue(env, {
        level: "info",
        requestId,
        message: `Starting threat intel fetch for ${threatIntelFeeds.length} feeds`,
      });

      let allThreatIntel = [];
      for (const feed of threatIntelFeeds) {
        const feedData = await fetchThreatIntelData(
          feed.url,
          feed.type,
          env,
          requestId
        );
        allThreatIntel = [...allThreatIntel, ...feedData];
      }

      // Process and store data
      const relevantIndicators = filterRelevantThreatIntel(allThreatIntel);
      await storeInD1(d1, relevantIndicators, env, requestId);
      await storeInFaunaDB(relevantIndicators, fauna, env, requestId);

      return new Response("Success", { status: 200 });
    } catch (error) {
      console.error(`[${requestId}] Error: ${error.message}`);
      await sendToLogQueue(env, {
        level: "error",
        requestId,
        message: error.message,
        stack: error.stack,
      });
      return new Response(`Error: ${error.message}`, { status: 500 });
    }
  },
};

async function fetchThreatIntelData(url, type, env, requestId) {
  try {
    const requestBody = {
      from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    };

    const response = await fetch(url, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: env.MISP_API_KEY,
      },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    // Return the data variable
    return data.response.Event || [];
  } catch (error) {
    console.error(`[${requestId}] Fetch error: ${error.message}`);
    await sendToLogQueue(env, {
      level: "error",
      requestId,
      message: `Fetch error: ${error.message}`,
    });
    throw error;
  }
}

function filterRelevantThreatIntel(events) {
  return events.flatMap((event) =>
    event?.Attribute?.map((attr) => ({
      type: attr.type,
      value: attr.value,
      category: attr.category,
      timestamp: attr.timestamp,
      comment: attr.comment,
    })) || []
  );
}

async function storeInFaunaDB(data, fauna, env, requestId) {
  try {
    for (const threat of data) {
      await fauna.query(fql`Threats.create({ data: ${threat} })`);
    }
  } catch (error) {
    console.error(`[${requestId}] Fauna error: ${error.message}`);
    await sendToLogQueue(env, {
      level: "error",
      requestId,
      message: `Fauna error: ${error.message}`,
    });
    throw error;
  }
}

async function storeInD1(d1, data, env, requestId) {
  try {
    for (const threat of data) {
      const searchableText = `${threat.type} ${threat.value || ""} ${
        threat.description || ""
      }`;
      await d1
        .prepare(
          "INSERT INTO threat_intel (type, value, category, timestamp, comment, searchable_text) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(
          threat.type,
          threat.value || null,
          threat.category || null,
          threat.timestamp || null,
          threat.comment || null,
          searchableText
        )
        .run();
    }
  } catch (error) {
    console.error(`[${requestId}] D1 error: ${error.message}`);
    await sendToLogQueue(env, {
      level: "error",
      requestId,
      message: `D1 error: ${error.message}`,
    });
    throw error;
  }
}