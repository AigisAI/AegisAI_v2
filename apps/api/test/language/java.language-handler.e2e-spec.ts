import { JavaLanguageHandler } from '../../src/language/handlers/java.language-handler';

describe('JavaLanguageHandler', () => {
  it('exposes the MVP Java metadata and filtering rules', () => {
    const handler = new JavaLanguageHandler();

    expect(handler.getLanguage()).toBe('java');
    expect(handler.getFileExtensions()).toEqual(['.java']);
    expect(handler.getExcludePatterns()).toEqual([
      '**/test/**',
      '**/generated/**',
      '**/build/**',
      '**/target/**',
      '**/node_modules/**',
      '**/vendor/**'
    ]);
    expect(handler.getMaxFileSize()).toBe(100 * 1024);
  });

  it('supports Java source files and rejects other extensions', () => {
    const handler = new JavaLanguageHandler();

    expect(handler.supports('src/main/java/com/example/UserService.java')).toBe(true);
    expect(handler.supports('src/main/resources/application.yml')).toBe(false);
  });
});
