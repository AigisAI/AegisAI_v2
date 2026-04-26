import { PDFDocument } from 'pdf-lib';

import { PdfGeneratorService } from '../../src/report/services/pdf-generator.service';

describe('PdfGeneratorService', () => {
  it('produces a valid PDF buffer for a completed scan payload', async () => {
    const service = new PdfGeneratorService();

    const pdf = await service.generateScanReport({
      id: 'scan-1',
      branch: 'main',
      commitSha: 'commit-123',
      totalFiles: 12,
      totalLines: 420,
      vulnCritical: 1,
      vulnHigh: 2,
      vulnMedium: 0,
      vulnLow: 1,
      vulnInfo: 0,
      connectedRepo: {
        fullName: 'acme/service'
      },
      vulnerabilities: [
        {
          id: 'vuln-1',
          title: 'SQL Injection',
          severity: 'HIGH',
          filePath: 'src/App.java',
          lineStart: 42,
          fixSuggestion: 'Use prepared statements.'
        }
      ]
    } as never);

    expect(Buffer.isBuffer(pdf)).toBe(true);
    expect(pdf.subarray(0, 5).toString('utf8')).toBe('%PDF-');
  });

  it('spills long vulnerability lists onto additional pages', async () => {
    const service = new PdfGeneratorService();

    const pdf = await service.generateScanReport({
      id: 'scan-1',
      branch: 'main',
      commitSha: 'commit-123',
      totalFiles: 120,
      totalLines: 4200,
      vulnCritical: 5,
      vulnHigh: 10,
      vulnMedium: 15,
      vulnLow: 10,
      vulnInfo: 0,
      connectedRepo: {
        fullName: 'acme/service'
      },
      vulnerabilities: Array.from({ length: 80 }, (_, index) => ({
        id: `vuln-${index + 1}`,
        title: `Finding ${index + 1}`,
        severity: 'HIGH',
        filePath: `src/Finding${index + 1}.java`,
        lineStart: index + 1,
        fixSuggestion: 'Use prepared statements.'
      }))
    } as never);

    const loadedPdf = await PDFDocument.load(pdf);

    expect(loadedPdf.getPageCount()).toBeGreaterThan(1);
  });
});
