import * as XLSX from 'xlsx';
import { BadRequestException } from '@nestjs/common';

export interface ToothMoveData {
  extrusion: number;
  translationX: number;
  translationY: number;
  rotation: number;
  angulation: number;
  torque: number;
}

export const parseMovementExcel = (
  buffer: Buffer,
): Map<number, Record<string, ToothMoveData>> => {
  try {
    if (!buffer || buffer.length === 0) {
      throw new Error('File content is empty');
    }

    const workbook = XLSX.read(buffer, { type: 'buffer' });

    if (!workbook.SheetNames || workbook.SheetNames.length === 0) {
      throw new Error('No sheets found in file');
    }

    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const jsonData = XLSX.utils.sheet_to_json(sheet) as any[];

    const stepsMap = new Map<number, Record<string, ToothMoveData>>();

    jsonData.forEach((row) => {
      const cleanRow: any = {};
      Object.keys(row).forEach((k) => {
        cleanRow[k.toLowerCase().trim().replace(/_/g, '')] = row[k];
      });

      const step = parseInt(cleanRow['step'] || cleanRow['stage']);
      const tooth = String(cleanRow['tooth'] || cleanRow['toothid']);

      if (isNaN(step) || !tooth || tooth === 'undefined') return;

      if (!stepsMap.has(step)) {
        stepsMap.set(step, {});
      }

      const stepData = stepsMap.get(step)!;

      stepData[tooth] = {
        extrusion: parseFloat(cleanRow['extrusion'] || 0),
        translationX: parseFloat(
          cleanRow['translationx'] || cleanRow['transx'] || 0,
        ),
        translationY: parseFloat(
          cleanRow['translationy'] || cleanRow['transy'] || 0,
        ),
        rotation: parseFloat(cleanRow['rotation'] || cleanRow['rot'] || 0),
        angulation: parseFloat(cleanRow['angulation'] || cleanRow['ang'] || 0),
        torque: parseFloat(cleanRow['torque'] || cleanRow['tor'] || 0),
      };
    });

    return stepsMap;
  } catch (error: any) {
    throw new BadRequestException('Invalid Excel/CSV format: ' + error.message);
  }
};
