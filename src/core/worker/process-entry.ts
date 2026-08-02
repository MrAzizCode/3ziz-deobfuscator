import { handleWorkerMessage } from "./handler";

let queue = Promise.resolve();

process.on("message", (message: unknown) => {
  queue = queue
    .then(async () => {
      const response = await handleWorkerMessage(message);
      if (typeof process.send === "function" && process.connected) {
        process.send(response);
      }
    })
    .catch((error: unknown) => {
      if (typeof process.send === "function" && process.connected) {
        process.send({
          type: "analysis-error",
          requestId: "unknown",
          error:
            error instanceof Error
              ? error.message
              : "Static worker encountered an internal error.",
        });
      }
    });
});

