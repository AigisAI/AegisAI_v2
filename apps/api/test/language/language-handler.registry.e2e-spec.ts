import { JavaLanguageHandler } from '../../src/language/handlers/java.language-handler';
import { LanguageHandlerRegistry } from '../../src/language/language-handler.registry';

describe('LanguageHandlerRegistry', () => {
  it('registers and resolves handlers by language key', () => {
    const registry = new LanguageHandlerRegistry();
    const javaHandler = new JavaLanguageHandler();

    registry.register(javaHandler);

    expect(registry.get('java')).toBe(javaHandler);
  });

  it('throws for unsupported languages', () => {
    const registry = new LanguageHandlerRegistry();

    expect(() => registry.get('kotlin')).toThrow('Unsupported language: kotlin');
  });
});
