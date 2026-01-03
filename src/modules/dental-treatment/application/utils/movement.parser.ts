import * as XLSX from 'xlsx';
import * as cheerio from 'cheerio';
import { BadRequestException } from '@nestjs/common';

// ==========================================
// 1. DATA STRUCTURES
// ==========================================
export interface ToothMoveData {
  rotation: number;
  angulation: number;
  inclination: number;
  translationX: number;
  translationY: number;
  translationZ: number;
  iprMesial: number;
  iprDistal: number;
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
      rowData['extrusionintrusion'] ||
      rowData['extrusionintrusioni'] // Fix cho trường hợp gộp text
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
  console.log(`[Parser] Strategy: Flat CSV/Excel. Rows: ${jsonData.length}`);
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
  console.log(`[Parser] Strategy: Excel Report`);
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
  console.log(`[Parser] Strategy: HTML (Cheerio). Content length: ${htmlContent.length}`);
  const $ = cheerio.load(htmlContent);
  const stepsMap: ParsedMovementMap = new Map();

  let tableCount = 0;

  // Tìm tất cả các bảng OrthoAutoTable
  $('table.OrthoAutoTable').each((tableIndex, tableElement) => {
    tableCount++;
    // Logic: Giả định bảng xuất hiện tuần tự là Step 1, Step 2...
    let stepIndex = 0;

    // Tìm caption
    const captionText =
      $(tableElement).find('caption').text() ||
      $(tableElement).prev().text() ||
      $(tableElement).parent().prev().text();

    console.log(`[Parser] Found Table #${tableIndex}. Caption: "${captionText}"`);

    const stepMatch = captionText.match(/(?:subsetup|stage|step)\s*(\d+)/i);
    if (stepMatch) {
      stepIndex = parseInt(stepMatch[1], 10);
    } else {
      // Fallback nếu không tìm thấy số step trong caption (vd: "FINAL")
      // Bỏ qua các bảng không phải movement data (vd: Tooth Width Analysis)
      const headerText = $(tableElement).text().toLowerCase();
      if(!headerText.includes("rotation") && !headerText.includes("angulation")) {
        return; // Skip bảng không phải movement
      }
      // Nếu là bảng FINAL ở cuối mà không có số -> Gán ID lớn
      if (captionText.toUpperCase().includes("FINAL")) {
        stepIndex = 999;
      }
    }

    if (stepIndex === 0) return; // Skip nếu không xác định được step

    if (!stepsMap.has(stepIndex)) stepsMap.set(stepIndex, {});
    const stepData = stepsMap.get(stepIndex)!;

    // Parse Headers
    const headers: string[] = [];
    $(tableElement)
      .find('tr') // Tìm tất cả row, row đầu tiên thường là header
      .eq(0)
      .find('td, th')
      .each((_, cell) => {
        headers.push(normalizeHeader($(cell).text()));
      });

    // Parse Data Rows
    $(tableElement)
      .find('tr')
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

        // Tìm cột Tooth Number
        const toothVal = cleanValue(rowData['toothnumber'] || rowData['tooth']);
        if (!toothVal) return;

        const tooth = String(toothVal);
        stepData[tooth] = mapRowToData(rowData);
      });
  });

  console.log(`[Parser] HTML Parse complete. Found ${stepsMap.size} steps from ${tableCount} tables.`);
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

    // ✅ FIX: Logic nhận diện HTML lỏng hơn để chấp nhận file thiếu <html> hoặc <!DOCTYPE>
    const isHtml =
      contentStr.includes('<table') ||
      contentStr.includes('<head') ||
      contentStr.includes('<body') ||
      (contentStr.startsWith('<') && contentStr.includes('OrthoSheet')); // Class đặc thù trong file của bạn

    if (isHtml) {
      return parseHtmlFormat(contentStr);
    }

    // 2. Detect Excel / CSV
    console.log(`[Parser] Detecting as Excel/CSV...`);
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    const sheet = workbook.Sheets[workbook.SheetNames[0]];

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
    console.error(`[Parser Error]`, error);
    throw new BadRequestException(
      'Failed to parse movement data: ' + error.message,
    );
  }
};