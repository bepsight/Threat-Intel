
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

export async function sendToLogQueue(env, logEntry) {
  if (!env?.MY_QUEUE) {
    console.error('Queue not configured');
    return;
  }

  // Add log entry to the queue
  logQueue.push({
    ...logEntry,
    timestamp: logEntry.timestamp || new Date().toISOString(),
  });

  // Log the entire logEntry object for inspection
  //console.log('sendToLogQueue: logEntry:', JSON.stringify(logEntry, null, 2));

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
          console.log(`sendToLogQueue: Sending batch of ${messages.length} log entries to queue with Batch ID: ${batchID}`);

          // Use sendBatch to reduce subrequests
          await env.MY_QUEUE.sendBatch(messages);

          console.log(`sendToLogQueue: Batch of ${messages.length} log entries sent to queue with Batch ID: ${batchID}`);
          subrequestsMade++;
          break;
        } catch (error) {
          retries++;
          console.error(`sendToLogQueue: Error sending batch to queue with Batch ID: ${batchID} (attempt ${retries}):`, error);
          if (retries === MAX_RETRIES) {
            console.error(`sendToLogQueue: Max retries reached, skipping batch with Batch ID: ${batchID}`);
          } else {
            // Exponential backoff
            await new Promise(resolve => setTimeout(resolve, 1000 * retries));
          }
        }

        if (subrequestsMade >= MAX_SUBREQUESTS) {
          console.log('Maximum subrequest limit reached during retries, exiting processing');
          break;
        }
      }

      if (subrequestsMade >= MAX_SUBREQUESTS) {
        break;
      }
    }
  } catch (error) {
    console.error('sendToLogQueue: Error sending to queue:', error);
  } finally {
    isSendingLogs = false;
  }
}
