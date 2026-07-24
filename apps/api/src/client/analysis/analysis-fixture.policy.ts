export function isMockAnalysisFixtureEnabled(
  environment: Readonly<Record<string, string | undefined>> = process.env
): boolean {
  return (
    environment.NODE_ENV === 'test' &&
    (environment.ANALYSIS_CLIENT_MODE ?? 'mock') === 'mock'
  );
}
