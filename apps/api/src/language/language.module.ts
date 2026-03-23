import { Module, OnModuleInit } from '@nestjs/common';

import { JavaLanguageHandler } from './handlers/java.language-handler';
import { LanguageHandlerRegistry } from './language-handler.registry';

@Module({
  providers: [LanguageHandlerRegistry, JavaLanguageHandler],
  exports: [LanguageHandlerRegistry]
})
export class LanguageModule implements OnModuleInit {
  constructor(
    private readonly registry: LanguageHandlerRegistry,
    private readonly javaLanguageHandler: JavaLanguageHandler
  ) {}

  onModuleInit(): void {
    this.registry.register(this.javaLanguageHandler);
  }
}
