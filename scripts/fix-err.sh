#!/bin/bash

# Đường dẫn tới các file cần refactor
SERVICE_FILE="src/modules/dental/application/services/dental.service.ts"
PARSER_FILE="src/modules/dental/application/utils/movement.parser.ts"

echo "🚀 Bắt đầu refactoring để sửa lỗi upload CSV..."

# 1. Sao lưu file trước khi sửa
cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
cp "$PARSER_FILE" "${PARSER_FILE}.bak"

# 2. Refactor dental.service.ts
# Tìm hàm processMovementExcel và thay thế toàn bộ thân hàm
perl -i -0777 -pe 's/async processMovementExcel\(file: Express.Multer.File, caseId: string\) \{.*?try \{.*?const stepsDataMap = parseMovementExcel\(file.buffer\);.*?return \{ message: .*? \};.*?\} catch \(error: any\) \{.*?throw new BadRequestException\(.*?\);.*?\}.*?\}/async processMovementExcel(file: Express.Multer.File, caseId: string) {
      this.logger.info(`Processing Movement Excel for Case: \${caseId}`);
      try {
          \/\/ Đọc dữ liệu từ ổ cứng vì buffer bị undefined khi dùng diskStorage
          const fileBuffer = await fs.readFile(file.path);
          const stepsDataMap = parseMovementExcel(fileBuffer);
          let count = 0;

          for (const [stepIndex, teethData] of stepsDataMap.entries()) {
              await this.orthoRepo.updateStepMovementData(caseId, stepIndex, teethData);
              count++;
          }

          \/\/ Xóa file tạm sau khi thành công
          await fs.remove(file.path).catch(() => {});

          this.logger.info(`Updated movement data for \${count} steps.`);
          return { message: "Movement data updated successfully", stepsCount: count };

      } catch (error: any) {
          \/\/ Đảm bảo xóa file tạm kể cả khi lỗi
          if (file?.path) await fs.remove(file.path).catch(() => {});
          this.logger.error(`Excel Parse Error`, error);
          throw new BadRequestException(`Failed to parse file: \${error.message}`);
      }
  }/sg' "$SERVICE_FILE"

# 3. Refactor movement.parser.ts
# Thay thế toàn bộ nội dung file để đảm bảo tính an toàn (Type-safe)
cat << 'EOF' > "$PARSER_FILE"
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

export const parseMovementExcel = (buffer: Buffer): Map<number, Record<string, ToothMoveData>> => {
  try {
    if (!buffer || buffer.length === 0) {
      throw new Error("File content is empty");
    }

    const workbook = XLSX.read(buffer, { type: 'buffer' });

    if (!workbook.SheetNames || workbook.SheetNames.length === 0) {
      throw new Error("No sheets found in file");
    }

    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const jsonData = XLSX.utils.sheet_to_json(sheet) as any[];

    const stepsMap = new Map<number, Record<string, ToothMoveData>>();

    jsonData.forEach((row) => {
        const cleanRow: any = {};
        Object.keys(row).forEach(k => {
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
            translationX: parseFloat(cleanRow['translationx'] || cleanRow['transx'] || 0),
            translationY: parseFloat(cleanRow['translationy'] || cleanRow['transy'] || 0),
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
EOF

echo "✅ Refactor hoàn tất!"
echo "📁 Backup đã được tạo tại *.bak"
echo "🛠️  Vui lòng khởi động lại server NestJS để áp dụng thay đổi."
