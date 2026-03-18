import { Injectable } from "@nestjs/common";

@Injectable()
export class AppService {
  getBootstrapState() {
    return {
      docs: "specs/001-aegisai-mvp-foundation/quickstart.md",
      service: "api",
      status: "bootstrapped"
    };
  }
}
