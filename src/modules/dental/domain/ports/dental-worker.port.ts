export const IDentalWorker = Symbol('IDentalWorker');

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
}

export interface WorkerResult {
  success: boolean;
  path: string;
}

export interface IDentalWorker {
  runTask(task: ConversionJob): Promise<WorkerResult>;
}
