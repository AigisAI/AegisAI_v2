import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { handleAiAdvisoryRequest } from "./advisory-runtime";

export function createAiRuntimeServer() {
  return createServer(async (incomingRequest, outgoingResponse) => {
    try {
      const request = await toFetchRequest(incomingRequest);
      const response = await handleAiAdvisoryRequest(request);

      await writeFetchResponse(response, outgoingResponse);
    } catch (error) {
      const message = error instanceof Error ? error.message : "AI runtime request failed.";
      outgoingResponse.writeHead(500, { "content-type": "application/json" });
      outgoingResponse.end(JSON.stringify({ error: message }));
    }
  });
}

async function toFetchRequest(incomingRequest: IncomingMessage): Promise<Request> {
  const host = incomingRequest.headers.host ?? "127.0.0.1";
  const protocol = host.startsWith("localhost") || host.startsWith("127.0.0.1") ? "http" : "https";
  const chunks: Buffer[] = [];

  for await (const chunk of incomingRequest) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return new Request(`${protocol}://${host}${incomingRequest.url ?? "/"}`, {
    method: incomingRequest.method,
    headers: incomingRequest.headers as HeadersInit,
    body: chunks.length > 0 ? Buffer.concat(chunks) : undefined
  });
}

async function writeFetchResponse(response: Response, outgoingResponse: ServerResponse): Promise<void> {
  response.headers.forEach((value, key) => {
    outgoingResponse.setHeader(key, value);
  });
  outgoingResponse.writeHead(response.status);
  outgoingResponse.end(Buffer.from(await response.arrayBuffer()));
}

if (require.main === module) {
  const port = Number(process.env.AI_PORT ?? 8000);

  createAiRuntimeServer().listen(port, () => {
    console.log(`AegisAI advisory runtime listening on ${port}`);
  });
}
