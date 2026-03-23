export interface ILanguageHandler {
  getLanguage(): string;
  getFileExtensions(): string[];
  getExcludePatterns(): string[];
  getMaxFileSize(): number;
  supports(path: string): boolean;
}
