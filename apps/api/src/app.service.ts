import { Injectable } from "@nestjs/common";

@Injectable()
export class AppService {
  getBootstrapState() {
    return {
      docs: "specs/002-production-scan-architecture/quickstart.md",
      service: "api",
      status: "bootstrapped"
    };
  }
}
