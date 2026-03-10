export const IDentalWorker = Symbol('IDentalWorker');

export interface ConversionBinaries {
  obj2gltf: string;
  gltfPipeline: string;
  gltfTransform: string;
}

export interface ConversionJob {
  objFilePath: string;
  outputDir: string;
  baseName: string;
  encryptionKey: string;
  config: {
    ratio: number;
    threshold: number;
    timeout: number;
  };
  // ✅ NEW: Truyền đường dẫn binaries vào Job
  binaries: ConversionBinaries;
}

export interface WorkerResult {
  success: boolean;
  path: string;
}

export interface IDentalWorker {
  runTask(task: ConversionJob): Promise<WorkerResult>;
}
