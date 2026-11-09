import { Module } from "@nestjs/common";

import { ScanDispatchService } from "./scan-dispatch.service";

@Module({ providers: [ScanDispatchService], exports: [ScanDispatchService] })
export class DispatchModule {}
