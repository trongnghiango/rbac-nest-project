import * as XLSX from 'xlsx';
import * as cheerio from 'cheerio';
import { BadRequestException } from '@nestjs/common';

// ==========================================
// 1. DATA STRUCTURES
// ==========================================
export interface ToothMoveData {
  rotation: number; // Rotation (deg)
  angulation: number; // Angulation / Tip (deg)
  inclination: number; // Inclination / Torque (deg)
  translationX: number; // Left/ Right (mm)
  translationY: number; // Forward/ Backward (mm)
  translationZ: number; // Extrusion/ Intrusion (mm)
  iprMesial: number; // IPR (mm)
  iprDistal: number; // IPR (mm)
}

export type ParsedMovementMap = Map<number, Record<string, ToothMoveData>>;

// ==========================================
// 2. HELPER FUNCTIONS
// ==========================================

/**
 * Làm sạch chuỗi số có đơn vị. VD: "0.38 deg" -> 0.38
 */
function cleanValue(val: any): number {
  if (typeof val === 'number') return val;
  if (!val) return 0;
  // Giữ lại số, dấu chấm, dấu trừ. Loại bỏ chữ cái và khoảng trắng.
  const str = String(val)
    .replace(/[^\d.-]/g, '')
    .trim();
  const num = parseFloat(str);
  return isNaN(num) ? 0 : num;
}

/**
 * Chuẩn hóa tên cột để dễ map. VD: "Left/ Right" -> "leftright"
 */
function normalizeHeader(header: string): string {
  return String(header)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}

/**
 * Map dữ liệu từ row (object key-value) sang ToothMoveData
 */
function mapRowToData(rowData: any): ToothMoveData {
  return {
    rotation: cleanValue(rowData['rotation'] || rowData['rot']),
    angulation: cleanValue(rowData['angulation'] || rowData['ang']),
    inclination: cleanValue(
      rowData['inclination'] || rowData['torque'] || rowData['tor'],
    ),
    translationX: cleanValue(
      rowData['translationx'] || rowData['transx'] || rowData['leftright'],
    ),
    translationY: cleanValue(
      rowData['translationy'] ||
        rowData['transy'] ||
        rowData['forwardbackward'],
    ),
    translationZ: cleanValue(
      rowData['extrusion'] ||
        rowData['translationz'] ||
        rowData['extrusionintrusion'],
    ),
    iprMesial: cleanValue(rowData['iprmesial']),
    iprDistal: cleanValue(rowData['iprdistal']),
  };
}

// ==========================================
// 3. PARSING STRATEGIES
// ==========================================

/**
 * STRATEGY 1: Parse CSV/Excel phẳng (Flat Format)
 */
function parseFlatFormat(jsonData: any[]): ParsedMovementMap {
  const stepsMap: ParsedMovementMap = new Map();

  jsonData.forEach((row) => {
    const cleanRow: any = {};
    Object.keys(row).forEach((k) => {
      cleanRow[normalizeHeader(k)] = row[k];
    });

    const step = parseInt(cleanRow['step'] || cleanRow['stage']);
    const tooth = String(
      cleanRow['tooth'] || cleanRow['toothid'] || cleanRow['toothnumber'],
    );

    if (isNaN(step) || !tooth || tooth === 'undefined') return;

    if (!stepsMap.has(step)) stepsMap.set(step, {});
    const stepData = stepsMap.get(step)!;

    stepData[tooth] = mapRowToData(cleanRow);
  });

  return stepsMap;
}

/**
 * STRATEGY 2: Parse Excel Report (Nhiều bảng con trong 1 sheet)
 */
function parseExcelReportFormat(sheet: XLSX.WorkSheet): ParsedMovementMap {
  const stepsMap: ParsedMovementMap = new Map();
  const rows = XLSX.utils.sheet_to_json(sheet, { header: 1 }) as any[][];

  let currentStep = 0;
  let headers: string[] = [];
  let isReadingTable = false;

  const stepHeaderRegex = /(?:subsetup|stage|step)\s*(\d+)/i;

  for (const row of rows) {
    const firstCell = row[0] ? String(row[0]).trim() : '';

    // Tìm header Step (vd: "FINAL Subsetup1")
    const stepMatch = firstCell.match(stepHeaderRegex);
    if (stepMatch) {
      currentStep = parseInt(stepMatch[1], 10);
      isReadingTable = false;
      continue;
    }

    // Tìm header cột (vd: "Tooth number")
    if (row.some((cell) => String(cell).toLowerCase().includes('tooth'))) {
      headers = row.map((cell) => normalizeHeader(String(cell)));
      isReadingTable = true;
      if (!stepsMap.has(currentStep)) stepsMap.set(currentStep, {});
      continue;
    }

    // Đọc data
    if (isReadingTable && currentStep > 0) {
      const toothNum = parseInt(firstCell);
      if (isNaN(toothNum)) continue;

      const toothStr = String(toothNum);
      const rowData: any = {};
      row.forEach((cell, index) => {
        if (headers[index]) rowData[headers[index]] = cell;
      });

      const stepData = stepsMap.get(currentStep)!;
      stepData[toothStr] = mapRowToData(rowData);
    }
  }
  return stepsMap;
}

/**
 * STRATEGY 3: Parse HTML Report (Sử dụng Cheerio)
 */
function parseHtmlFormat(htmlContent: string): ParsedMovementMap {
  const $ = cheerio.load(htmlContent);
  const stepsMap: ParsedMovementMap = new Map();

  // Tìm tất cả các bảng OrthoAutoTable
  $('table.OrthoAutoTable').each((tableIndex, tableElement) => {
    // Logic: Giả định bảng xuất hiện tuần tự là Step 1, Step 2...
    let stepIndex = tableIndex + 1;

    // Cố gắng tìm text Step trong caption hoặc div cha nếu có
    const captionText =
      $(tableElement).find('caption').text() ||
      $(tableElement).prev().text() ||
      $(tableElement).parent().prev().text();

    const stepMatch = captionText.match(/(?:subsetup|stage|step)\s*(\d+)/i);
    if (stepMatch) {
      stepIndex = parseInt(stepMatch[1], 10);
    }

    if (!stepsMap.has(stepIndex)) stepsMap.set(stepIndex, {});
    const stepData = stepsMap.get(stepIndex)!;

    // Parse Headers
    const headers: string[] = [];
    $(tableElement)
      .find('tbody tr')
      .eq(0)
      .find('td')
      .each((_, cell) => {
        headers.push(normalizeHeader($(cell).text()));
      });

    // Parse Data Rows
    $(tableElement)
      .find('tbody tr')
      .slice(1)
      .each((_, row) => {
        const cells = $(row).find('td');
        const rowData: any = {};

        cells.each((cellIndex, cell) => {
          const header = headers[cellIndex];
          if (header) {
            rowData[header] = $(cell).text();
          }
        });

        const toothVal = cleanValue(rowData['toothnumber'] || rowData['tooth']);
        if (!toothVal) return;

        const tooth = String(toothVal);
        stepData[tooth] = mapRowToData(rowData);
      });
  });

  return stepsMap;
}

// ==========================================
// 4. MAIN EXPORT
// ==========================================

export const parseMovementData = (
  buffer: Buffer,
  filename: string = 'unknown',
): ParsedMovementMap => {
  try {
    if (!buffer || buffer.length === 0) {
      throw new Error('File content is empty');
    }

    const contentStr = buffer.toString('utf-8').trim();

    // 1. Detect HTML
    if (
      contentStr.startsWith('<') &&
      (contentStr.includes('<html') || contentStr.includes('<!DOCTYPE'))
    ) {
      return parseHtmlFormat(contentStr);
    }

    // 2. Detect Excel / CSV
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    const sheet = workbook.Sheets[workbook.SheetNames[0]];

    // Check Flat vs Report format
    // FIX: Removed 'limit: 1' as it is not a valid option in Sheet2JSONOpts
    const firstRow: any[] = XLSX.utils.sheet_to_json(sheet, {
      header: 1,
      range: 0,
    })[0] as any[];
    const isFlat =
      firstRow &&
      firstRow.some((cell) => normalizeHeader(String(cell)) === 'step');

    if (isFlat) {
      const jsonData = XLSX.utils.sheet_to_json(sheet);
      return parseFlatFormat(jsonData);
    } else {
      return parseExcelReportFormat(sheet);
    }
  } catch (error: any) {
    throw new BadRequestException(
      'Failed to parse movement data: ' + error.message,
    );
  }
};
