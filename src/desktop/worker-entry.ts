import { handleWorkerMessage } from "../core/worker/handler";

const parentPort = process.parentPort;

if (parentPort === undefined || parentPort === null) {
  throw new Error("The static analysis worker requires an Electron parent port.");
}

let handled = false;

parentPort.on("message", (event) => {
  if (handled) {
    parentPort.postMessage({
      type: "analysis-error",
      requestId: "unknown",
      error: "This bounded worker accepts exactly one analysis request.",
    });
    return;
  }
  handled = true;
  void handleWorkerMessage(event.data)
    .then((response) => {
      parentPort.postMessage(response);
    })
    .catch((error: unknown) => {
      parentPort.postMessage({
        type: "analysis-error",
        requestId: "unknown",
        error:
          error instanceof Error
            ? error.message
            : "Static analysis worker failed safely.",
      });
    });
});
