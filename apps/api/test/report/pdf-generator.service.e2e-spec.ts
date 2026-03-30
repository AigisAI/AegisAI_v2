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
});
