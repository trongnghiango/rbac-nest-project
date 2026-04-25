import { Injectable, Logger, Inject } from '@nestjs/common';
import { DRIZZLE } from '@database/drizzle.provider';
import { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from '@database/schema';
import { eq } from 'drizzle-orm';

@Injectable()
export class CrmLegacyMigrationService {
    private readonly logger = new Logger(CrmLegacyMigrationService.name);

    constructor(
        @Inject(DRIZZLE) private readonly db: NodePgDatabase<typeof schema>
    ) { }

    async migrateClients(rawData: any[]) {
        this.logger.log(`🚀 Bắt đầu di cư ${rawData.length} khách hàng (Clients)...`);
        let statistics = { success: 0, failed: 0, existing: 0 };

        for (const r of rawData) {
            try {
                // Fields mapped from index because headers are messy
                const taxCode = r[1]?.trim() || null;
                const companyName = r[2]?.trim();
                const address = r[3]?.trim() || null;
                const legalRep = r[4]?.trim() || null;
                const repPhone = r[5]?.trim() || null;
                const contactName = r[6]?.trim() || legalRep || 'Unknown Contact';
                const contactPhone = r[7]?.trim() || repPhone || null;
                const contactEmail = r[8]?.trim() || null;
                const contractSignDate = r[9]?.trim() || null;
                const contractNo = r[10]?.trim() || null;
                const rawStatus = r[11]?.trim() || '';
                const feeType = r[12]?.trim() || null;
                const expectedFee = r[20]?.trim() || null;
                const suspendDeadline = r[21]?.trim() || null;
                const serviceDesc = r[22]?.trim() || null;
                const remarks = r[23]?.trim() || null;

                if (!companyName) continue; // Skip empty rows

                let orgStatus: 'ACTIVE' | 'PROSPECT' | 'INACTIVE' | 'CHURNED' = 'ACTIVE';
                const lowerStatus = rawStatus.toLowerCase();
                if (lowerStatus.includes('thanh lý') || lowerStatus.includes('one off') || lowerStatus.includes('tạm ngưng')) {
                    orgStatus = 'INACTIVE';
                } else if (lowerStatus.includes('chờ ký')) {
                    orgStatus = 'PROSPECT';
                }

                let wasInserted = false;

                await this.db.transaction(async (tx) => {
                    // Check if exists
                    let existingOrg = null;
                    if (taxCode && taxCode.length > 5) {
                        existingOrg = await tx.query.organizations.findFirst({
                            where: eq(schema.organizations.tax_code, taxCode)
                        });
                    }

                    if (!existingOrg) {
                        existingOrg = await tx.query.organizations.findFirst({
                            where: eq(schema.organizations.company_name, companyName)
                        });
                    }

                    if (existingOrg) {
                        statistics.existing++;
                        return; // exit transaction early
                    }

                    // Insert Organization
                    const [newOrg] = await tx.insert(schema.organizations).values({
                        company_name: companyName,
                        tax_code: taxCode,
                        type: 'ENTERPRISE',
                        address: address,
                        status: orgStatus,
                        note: remarks,
                        metadata: {
                            legacy_data: r,
                            feeType,
                            expectedFee,
                            contractSignDate,
                            contractNo,
                            suspendDeadline,
                            serviceDesc,
                            original_status: rawStatus
                        }
                    }).returning({ id: schema.organizations.id });

                    // Insert Primary Contact
                    await tx.insert(schema.contacts).values({
                        organization_id: newOrg.id,
                        full_name: contactName || 'Chưa cập nhật',
                        phone: contactPhone,
                        email: contactEmail,
                        is_primary: true,
                        metadata: {
                            legal_representative: legalRep
                        }
                    });

                    wasInserted = true;
                });
                
                if (wasInserted) statistics.success++;
            } catch (e) {
                this.logger.error(`Lỗi dòng: ${r[2]} - ${e.message}`);
                statistics.failed++;
            }
        }
        this.logger.log(`✅ Migration Clients xong: ${statistics.success} tạo mới, ${statistics.existing} đã tồn tại, ${statistics.failed} lỗi.`);
        
        console.log(`\n--- KẾT QUẢ DI CƯ CLIENTS ---`);
        console.log(`✅ Tạo mới: ${statistics.success}`);
        console.log(`🔄 Tồn tại: ${statistics.existing}`);
        console.log(`❌ Lỗi:    ${statistics.failed}`);
        console.log(`------------------------------`);

        return statistics;
    }
}
