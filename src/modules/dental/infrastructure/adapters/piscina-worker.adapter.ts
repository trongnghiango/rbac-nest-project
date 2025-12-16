import { Injectable, Inject } from '@nestjs/common';
import Piscina from 'piscina';
import {
  IDentalWorker,
  ConversionJob,
  WorkerResult,
} from '../../domain/ports/dental-worker.port';
import { PISCINA_POOL } from '../workers/piscina.provider';

@Injectable()
export class PiscinaDentalWorker implements IDentalWorker {
  constructor(@Inject(PISCINA_POOL) private readonly pool: Piscina) {}

  async runTask(task: ConversionJob): Promise<WorkerResult> {
    return this.pool.run(task);
  }
}
