import { context, ROOT_CONTEXT, SpanStatusCode, trace } from "@opentelemetry/api";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { BatchSpanProcessor, type ReadableSpan, type SpanProcessor } from "@opentelemetry/sdk-trace-base";
import type { NextFunction, Request, Response } from "express";
import { logs, SeverityNumber } from "@opentelemetry/api-logs";
import { OTLPLogExporter } from "@opentelemetry/exporter-logs-otlp-http";
import { BatchLogRecordProcessor, type LogRecordProcessor, type ReadableLogRecord } from "@opentelemetry/sdk-logs";
import { createServer, type Server } from "node:http";

const ROUTES = new Set(["/api/auth/me", "/api/auth/github", "/api/auth/github/callback", "/api/auth/logout",
  "/api/runtime/scans/:scanRequestId", "/api/runtime/scans/:scanRequestId/evidence",
  "/api/runtime/status", "/api/runtime/repositories", "/api/runtime/scans", "/api/health"]);
const BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5];

export function boundedRoute(path: string): string {
  if (ROUTES.has(path)) return path;
  if (/^\/api\/runtime\/scans\/scan_request_[A-Za-z0-9-]+$/.test(path)) return "/api/runtime/scans/:scanRequestId";
  if (/^\/api\/runtime\/scans\/scan_request_[A-Za-z0-9-]+\/evidence$/.test(path)) return "/api/runtime/scans/:scanRequestId/evidence";
  return "/unmatched";
}

interface Observation { count: number; seconds: number; buckets: number[]; }
export class RequestMeasurements {
  private readonly observations = new Map<string, Observation>();
  observe(route: string, method: string, status: number, seconds: number): void {
    const labels = `route="${boundedRoute(route)}",method="${method === "GET" || method === "POST" ? method : "OTHER"}",status_class="${Math.min(5, Math.max(1, Math.floor(status / 100)))}xx"`;
    const value = this.observations.get(labels) ?? { count: 0, seconds: 0, buckets: BUCKETS.map(() => 0) };
    value.count++; value.seconds += seconds;
    BUCKETS.forEach((limit, index) => { if (seconds <= limit) value.buckets[index]++; });
    this.observations.set(labels, value);
  }
  render(): string {
    const lines = ["# TYPE aegisai_http_request_duration_seconds histogram"];
    for (const [labels, value] of this.observations) {
      BUCKETS.forEach((limit, index) => lines.push(`aegisai_http_request_duration_seconds_bucket{${labels},le="${limit}"} ${value.buckets[index]}`));
      lines.push(`aegisai_http_request_duration_seconds_bucket{${labels},le="+Inf"} ${value.count}`,
        `aegisai_http_request_duration_seconds_count{${labels}} ${value.count}`,
        `aegisai_http_request_duration_seconds_sum{${labels}} ${value.seconds}`);
    }
    lines.push("# TYPE aegisai_api_resident_memory_bytes gauge", `aegisai_api_resident_memory_bytes ${process.memoryUsage().rss}`,
      "# TYPE aegisai_api_up gauge", "aegisai_api_up 1");
    return lines.join("\n") + "\n";
  }
}

export interface RuntimeTelemetry {
  middleware(request: Request, response: Response, next: NextFunction): void;
  shutdown(): Promise<void>;
}

export function safeHttpSpan(span: Pick<ReadableSpan, "instrumentationScope"|"attributes"|"events"|"links"|"status"|"name">): boolean {
  const allowed = new Set(["http.request.method", "http.route", "http.response.status_code"]);
  const method = span.attributes["http.request.method"];
  const route = span.attributes["http.route"];
  return span.instrumentationScope.name === "aegisai-private-http" &&
    (method === "GET" || method === "POST" || method === "OTHER") &&
    typeof route === "string" && boundedRoute(route) === route &&
    span.name === `${method} ${route}` && Object.keys(span.attributes).every(key => allowed.has(key)) &&
    span.events.length === 0 && span.links.length === 0 && !span.status.message;
}

export function safeHttpLog(record: Pick<ReadableLogRecord, "instrumentationScope"|"body"|"attributes">): boolean {
  if(record.instrumentationScope.name !== "aegisai-private-http" || typeof record.body !== "string") return false;
  try {
    const value=JSON.parse(record.body) as Record<string,unknown>;
    const allowed=new Set(["service","level","method","route","status","duration_ms","trace_id","span_id","time"]);
    return Object.keys(value).every(key=>allowed.has(key)) && value.service === "aegisai-api" &&
      (value.level === "error" || value.level === "info") &&
      (value.method === "GET" || value.method === "POST" || value.method === "OTHER") &&
      typeof value.route === "string" && boundedRoute(value.route) === value.route &&
      typeof value.status === "number" && value.status >= 100 && value.status < 600 &&
      typeof value.duration_ms === "number" && Number.isFinite(value.duration_ms) && value.duration_ms >= 0 &&
      typeof value.trace_id === "string" && /^[a-f0-9]{32}$/.test(value.trace_id) &&
      typeof value.span_id === "string" && /^[a-f0-9]{16}$/.test(value.span_id) &&
      typeof value.time === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value.time) &&
      Number.isFinite(Date.parse(value.time)) && Object.keys(record.attributes).length === 0;
  } catch {return false;}
}

export async function startRuntimeTelemetry(): Promise<RuntimeTelemetry | undefined> {
  if (process.env.RUNTIME_TELEMETRY_ENABLED !== "true") return undefined;
  const exporter = new OTLPTraceExporter({ url: "http://alloy:4318/v1/traces", timeoutMillis: 2000 });
  const batch = new BatchSpanProcessor(exporter, { maxQueueSize: 256, maxExportBatchSize: 32,
    scheduledDelayMillis: 1000, exportTimeoutMillis: 2500 });
  const processor: SpanProcessor = {
    onStart(span, parent) { batch.onStart(span, parent); },
    onEnd(span) { if (safeHttpSpan(span)) batch.onEnd(span); },
    forceFlush() { return batch.forceFlush(); },
    shutdown() { return batch.shutdown(); }
  };
  const logBatch = new BatchLogRecordProcessor({exporter:new OTLPLogExporter({url:"http://alloy:4318/v1/logs",timeoutMillis:2000}),
    maxQueueSize:128,maxExportBatchSize:16,scheduledDelayMillis:1000,exportTimeoutMillis:2500});
  const logProcessor:LogRecordProcessor={
    onEmit(record) {if(safeHttpLog(record))logBatch.onEmit(record);},
    forceFlush(){return logBatch.forceFlush();},shutdown(){return logBatch.shutdown();}
  };
  const sdk = new NodeSDK({ autoDetectResources: false,
    resource: resourceFromAttributes({ "service.name": "aegisai-api", "deployment.environment.name": "private-ec2" }),
    spanProcessors: [processor], logRecordProcessors:[logProcessor], metricReaders:[], instrumentations: [] });
  let server: Server | undefined;
  try {
    sdk.start();
    const measurements = new RequestMeasurements();
    server = createServer((request, response) => {
      if (request.method !== "GET" || request.url !== "/metrics") { response.writeHead(404).end(); return; }
      response.writeHead(200, { "Content-Type": "text/plain; version=0.0.4", "Connection": "close" });
      response.end(measurements.render());
    });
    server.maxConnections = 4;
    await new Promise<void>((resolve, reject) => { server!.once("error", reject); server!.listen(9465, "0.0.0.0", resolve); });
    const logger=logs.getLogger("aegisai-private-http");
    const tracer = trace.getTracer("aegisai-private-http");
    return {
      middleware(request, response, next) {
        const route = boundedRoute(request.path);
        const method = request.method === "GET" || request.method === "POST" ? request.method : "OTHER";
        const began = performance.now();
        // Never extract caller headers or automatically instrument SCM/AWS/SQL.
        const span = tracer.startSpan(`${method} ${route}`, { attributes: { "http.request.method": method, "http.route": route } }, ROOT_CONTEXT);
        let recorded = false;
        const complete = (status: number) => {
          if (recorded) return;
          recorded = true;
          const duration = (performance.now() - began) / 1000;
          measurements.observe(route, method, status, duration);
          span.setAttribute("http.response.status_code", status);
          if (status >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
          const reference = span.spanContext();
          span.end();
          if (route === "/api/health") return;
          const value = JSON.stringify({ service: "aegisai-api", level: status >= 500 ? "error" : "info",
            method, route, status, duration_ms: Math.round(duration * 1000),
            trace_id: reference.traceId, span_id: reference.spanId, time: new Date().toISOString() });
          logger.emit({body:value,severityNumber:status>=500?SeverityNumber.ERROR:SeverityNumber.INFO,
            context:trace.setSpan(ROOT_CONTEXT,span)});
        };
        response.once("finish", () => complete(response.statusCode));
        response.once("close", () => complete(response.writableFinished ? response.statusCode : 499));
        context.with(trace.setSpan(ROOT_CONTEXT, span), next);
      },
      async shutdown() {
        server!.closeAllConnections();
        await new Promise<void>(resolve => server!.close(() => resolve()));
        await Promise.race([sdk.shutdown(), new Promise<void>(resolve => { const timer = setTimeout(resolve, 3000); timer.unref(); })]);
      }
    };
  } catch {
    server?.close();
    await sdk.shutdown().catch(() => undefined);
    process.stderr.write("OPTIONAL_OBSERVABILITY_UNAVAILABLE\n");
    return undefined;
  }
}
