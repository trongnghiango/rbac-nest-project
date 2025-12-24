import * as XLSX from 'xlsx';
import { BadRequestException } from '@nestjs/common';

// Cấu trúc JSON lưu vào DB
export interface ToothMoveData {
  extrusion: number;
  translationX: number;
  translationY: number;
  rotation: number;
  angulation: number;
  torque: number;
}

export const parseMovementExcel = (buffer: Buffer): Map<number, Record<string, ToothMoveData>> => {
  try {
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];

    // Chuyển sang JSON: [[Step, Tooth, Ext...], [1, 11, 0.1...]]
    const jsonData = XLSX.utils.sheet_to_json(sheet) as any[];

    // Map: StepIndex -> { ToothID: Data }
    const stepsMap = new Map<number, Record<string, ToothMoveData>>();

    jsonData.forEach((row) => {
        // Chuẩn hóa key (viết thường, bỏ khoảng trắng) để dễ map
        const cleanRow: any = {};
        Object.keys(row).forEach(k => {
            cleanRow[k.toLowerCase().trim().replace(/_/g, '')] = row[k];
        });

        // Lấy Step và Tooth (bắt buộc)
        const step = parseInt(cleanRow['step'] || cleanRow['stage']);
        const tooth = String(cleanRow['tooth'] || cleanRow['toothid']);

        if (isNaN(step) || !tooth) return;

        if (!stepsMap.has(step)) {
            stepsMap.set(step, {});
        }

        const stepData = stepsMap.get(step)!;

        // Lưu dữ liệu vào object
        stepData[tooth] = {
            extrusion: parseFloat(cleanRow['extrusion'] || 0),
            translationX: parseFloat(cleanRow['translationx'] || cleanRow['transx'] || 0),
            translationY: parseFloat(cleanRow['translationy'] || cleanRow['transy'] || 0),
            rotation: parseFloat(cleanRow['rotation'] || cleanRow['rot'] || 0),
            angulation: parseFloat(cleanRow['angulation'] || cleanRow['ang'] || 0),
            torque: parseFloat(cleanRow['torque'] || cleanRow['tor'] || 0),
        };
    });

    return stepsMap;
  } catch (error: any) {
    throw new BadRequestException('Invalid Excel file format. ' + error.message);
  }
};
