export function readScanPlaneExports(moduleSource: string): string {
  const exportsBlock = moduleSource.match(
    /exports:\s*\[([\s\S]*?)\]\s*\n\}\)\s*export class ScanPlaneModule/u
  )?.[1];
  if (!exportsBlock) {
    throw new Error('Expected the ScanPlaneModule exports block.');
  }
  return exportsBlock;
}
