import { Global, Module } from "@nestjs/common";

import { RuntimeResourcesService } from "./runtime-resources.service";

@Global()
@Module({
  providers: [RuntimeResourcesService],
  exports: [RuntimeResourcesService]
})
export class RuntimeModule {}
