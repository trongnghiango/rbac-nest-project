import { Injectable, Inject } from '@nestjs/common';
import { IPatientRepository } from '../repositories/patient.repository';
import { CreatePatientDto, Gender } from '../../application/dtos/patient.dto';
import { Transaction } from '@core/shared/application/ports/transaction-manager.port';

@Injectable()
export class PatientService {
  constructor(
    @Inject(IPatientRepository) private readonly repo: IPatientRepository,
  ) {}

  async ensurePatientExists(
    data: {
      code: string;
      name: string;
      gender?: any;
      dob?: string; // Format YYYY-MM-DD
    },
    clinicId: number,
    tx?: Transaction,
  ): Promise<{ id: number }> {
    const existing = await this.repo.findPatientByCode(data.code, tx);
    if (existing) {
      // Có thể thêm logic validate xem patient này có thuộc clinicId kia không
      return existing;
    }

    // Map dữ liệu sang DTO chuẩn
    const newPatient: CreatePatientDto = {
      fullName: data.name,
      patientCode: data.code,
      clinicId: clinicId,
      gender: data.gender as Gender, // Cần đảm bảo input khớp Enum hoặc validate thêm
      birthDate: data.dob,
    };

    return this.repo.createPatient(newPatient, tx);
  }
}
