// Định nghĩa cấu trúc dữ liệu di chuyển của 1 răng (giống logic trong parser cũ)
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

// Map: "11" -> { rotation: ... }, "12" -> { ... }
export type TeethMovementRecord = Record<string, ToothMoveData>;

// DTO trả về cho API History
export interface CaseHistoryDTO {
  caseId: number;
  status: string | null;
  createdAt: Date | null;
  notes: string | null;
  productType: string;
  doctorName: string | null;
}

// Type mở rộng cho Conversion Job trong Service (kèm Metadata để tracking progress)
import { ConversionJob } from '../ports/dental-worker.port';

export type JawType = 'Maxillary' | 'Mandibular';

export type ConversionTaskWithMeta = ConversionJob & {
  meta: {
    index: number;
    type: JawType;
  };
};
