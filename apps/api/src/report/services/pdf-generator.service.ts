import { Injectable } from '@nestjs/common';
import { PDFDocument, StandardFonts } from 'pdf-lib';

interface ReportVulnerabilitySummary {
  id: string;
  title: string;
  severity: string;
  filePath: string;
  lineStart: number;
  fixSuggestion: string | null;
}

interface ReportScanSummary {
  id: string;
  branch: string;
  commitSha: string | null;
  totalFiles: number | null;
  totalLines: number | null;
  vulnCritical: number;
  vulnHigh: number;
  vulnMedium: number;
  vulnLow: number;
  vulnInfo: number;
  connectedRepo: {
    fullName: string;
  };
  vulnerabilities: ReportVulnerabilitySummary[];
}

@Injectable()
export class PdfGeneratorService {
  async generateScanReport(scan: ReportScanSummary): Promise<Buffer> {
    const pdf = await PDFDocument.create();
    const page = pdf.addPage([595, 842]);
    const font = await pdf.embedFont(StandardFonts.Helvetica);
    const boldFont = await pdf.embedFont(StandardFonts.HelveticaBold);

    let cursorY = 800;
    const drawLine = (text: string, weight: 'normal' | 'bold' = 'normal', size = 11) => {
      page.drawText(text, {
        x: 40,
        y: cursorY,
        size,
        font: weight === 'bold' ? boldFont : font
      });
      cursorY -= size + 8;
    };

    drawLine('AegisAI Scan Report', 'bold', 18);
    drawLine(`Repository: ${scan.connectedRepo.fullName}`);
    drawLine(`Branch: ${scan.branch}`);
    drawLine(`Commit: ${scan.commitSha ?? 'unknown'}`);
    drawLine(`Files: ${scan.totalFiles ?? 0} | Lines: ${scan.totalLines ?? 0}`);
    drawLine(
      `Severity Summary: C ${scan.vulnCritical} | H ${scan.vulnHigh} | M ${scan.vulnMedium} | L ${scan.vulnLow} | I ${scan.vulnInfo}`
    );
    cursorY -= 8;
    drawLine('Vulnerabilities', 'bold', 14);

    if (scan.vulnerabilities.length === 0) {
      drawLine('No vulnerabilities recorded for this scan.');
    } else {
      for (const vulnerability of scan.vulnerabilities.slice(0, 20)) {
        drawLine(
          `[${vulnerability.severity}] ${vulnerability.title} - ${vulnerability.filePath}:${vulnerability.lineStart}`,
          'bold',
          11
        );
        if (vulnerability.fixSuggestion) {
          drawLine(`Fix: ${vulnerability.fixSuggestion}`, 'normal', 10);
        }
      }
    }

    const bytes = await pdf.save();

    return Buffer.from(bytes);
  }
}
