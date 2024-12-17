// Export the sendToLogQueue function
export { sendToLogQueue };


////////////////////////////////////////////////////
// Function to send logs to queue
const logQueue = [];
let isSendingLogs = false;
let batchCounter = 0;

// Function to generate batch ID
function generateBatchID() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hour = String(now.getHours()).padStart(2, '0');
  const batchID = `${year}${month}${day}${hour}${String(batchCounter).padStart(9, '0')}`;
  batchCounter++;
  return batchID;
}

async function sendToLogQueue(env, logEntry) {
  if (!env?.MY_QUEUE) {
    console.error('Queue not configured');
    return;
  }

  // Add log entry to the queue
  logQueue.push({
    ...logEntry,
    timestamp: logEntry.timestamp || new Date().toISOString(),
  });

  // If already sending logs, return
  if (isSendingLogs) return;

  isSendingLogs = true;
  const MAX_SUBREQUESTS = 45; // Reserve some subrequests for other operations
  const BATCH_SIZE = 50; // Adjust as needed
  const MAX_RETRIES = 3;
  let subrequestsMade = 0;

  try {
    while (logQueue.length > 0) {
      if (subrequestsMade >= MAX_SUBREQUESTS) {
        console.log('Maximum subrequest limit reached, exiting processing');
        break;
      }

      // Take a batch from the queue
      const batch = logQueue.splice(0, BATCH_SIZE);
      const batchID = generateBatchID();

      // Prepare messages for sendBatch
      const messages = batch.map(entry => ({ body: JSON.stringify(entry) }));

      let retries = 0;
      while (retries < MAX_RETRIES) {
        try {
          await env.MY_QUEUE.sendBatch(messages);
          subrequestsMade++;
          break;
        } catch (error) {
          retries++;
          console.error(`Error sending batch (attempt ${retries}):`, error);
          if (retries === MAX_RETRIES) {
            console.error(`Max retries reached, skipping batch: ${batchID}`);
          } else {
            // Exponential backoff
            await new Promise(resolve => setTimeout(resolve, 1000 * retries));
          }
        }

        if (subrequestsMade >= MAX_SUBREQUESTS) {
          break;
        }
      }

      if (subrequestsMade >= MAX_SUBREQUESTS) {
        break;
      }
    }
  } catch (error) {
    console.error('Error sending to queue:', error);
  } finally {
    isSendingLogs = false;
  }
}

// Inside fetchThreatIntelData function, after fetching the response
const responseText = await response.text();
console.log(`Response Status: ${response.status} ${response.statusText}`);
console.log(`Response Body: ${responseText}`);

// Correct date calculation
if (lastFetchTime) {
  const fromDateString = new Date(lastFetchTime).toISOString();
  requestBody = { from: fromDateString };
} else {
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const thirtyDaysAgoString = thirtyDaysAgo.toISOString();
  requestBody = { from: thirtyDaysAgoString };
}

// Attempt to parse JSON if response is OK
try {
  if (response.ok) {
    const responseData = JSON.parse(responseText);
    data = responseData.response.Event || [];
  } else {
    throw new Error(`Failed to fetch ${type} data: ${response.status} ${response.statusText}`);
  }
} catch (error) {
  console.error(`Error fetching ${type} data: ${error.message}`);
  console.error(`Response Body: ${responseText}`);
  // Rest of the error handling...
}
