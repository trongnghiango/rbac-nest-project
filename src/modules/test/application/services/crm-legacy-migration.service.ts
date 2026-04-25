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

    async migrateLeads(rawData: any[]) {
        this.logger.log(`🚀 Bắt đầu di cư ${rawData.length} Leads (Cơ hội khách hàng)...`);
        let statistics = { success: 0, failed: 0 };

        for (const r of rawData) {
            try {
                // R[1] Ngày, R[2] Nick name, R[3] Tên khách hàng, R[4] Điện thoại, R[5] Nguồn
                const dateStr = r[1]?.trim();
                const nickName = r[2]?.trim();
                const customerName = r[3]?.trim();
                const phone = r[4]?.replace(/[^0-9]/g, ''); // Extract only digits
                const rawSource = r[5]?.trim() || '';
                const consultant = r[6]?.trim() || '';
                const rawStatus = r[7]?.trim() || '';
                const serviceNeed = r[8]?.trim() || '';
                const note = r[9]?.trim() || '';

                if (!nickName && !customerName && !phone) continue;

                // 1. Stage Mapping
                let stage: 'NEW' | 'CONSULTING' | 'NEGOTIATING' | 'WON' | 'LOST' = 'NEW';
                const s = rawStatus.toLowerCase();
                if (s.includes('từ chối') || s.includes('fail')) stage = 'LOST';
                else if (s.includes('chốt')) stage = 'WON';
                else if (s.includes('đã báo giá') || s.includes('đang tư vấn')) stage = 'CONSULTING';

                // 2. Source Mapping
                let source: 'REFERRAL' | 'WEBSITE' | 'COLD_CALL' | 'EVENT' | 'SOCIAL' | 'DIRECT' | 'ZALO' | 'OTHER' = 'OTHER';
                const src = rawSource.toLowerCase();
                if (src.includes('facebook') || src.includes('social')) source = 'SOCIAL';
                else if (src.includes('zalo')) source = 'ZALO';
                else if (src.includes('google')) source = 'WEBSITE';
                else if (src.includes('relationship') || src.includes('hội')) source = 'REFERRAL';

                await this.db.transaction(async (tx) => {
                    // Try to link with existing Contact / Organization by Phone
                    let orgId = null;
                    let contactId = null;
                    
                    if (phone && phone.length > 5) {
                        const existingContact = await tx.query.contacts.findFirst({
                            where: eq(schema.contacts.phone, phone)
                        });
                        if (existingContact) {
                            contactId = existingContact.id;
                            orgId = existingContact.organization_id;
                        }
                    }

                    // Try to guess Employee ID by Consultant Name
                    let assigneeId = null;
                    if (consultant) {
                         const employees = await tx.query.employees.findMany();
                         const matched = employees.find(e => {
                             const meta = e.metadata as any;
                             const fullNameStr = e.full_name as string;
                             const lastName = fullNameStr ? fullNameStr.split(' ').pop() : '';
                             return (fullNameStr && fullNameStr.includes(consultant)) || 
                                    (meta?.nicknames && meta.nicknames.includes(consultant)) || 
                                    (lastName && consultant.includes(lastName));
                         });
                         if (matched) assigneeId = matched.id;
                    }

                    const title = customerName || nickName || `Khách hàng ${phone || 'Không tên'}`;

                    await tx.insert(schema.leads).values({
                        title: title,
                        organization_id: orgId,
                        contact_id: contactId,
                        assigned_to_id: assigneeId,
                        service_need: serviceNeed,
                        stage: stage,
                        source: source,
                        note: note,
                        metadata: {
                            legacy_date: dateStr,
                            original_status: rawStatus,
                            original_consultant: consultant,
                            raw_phone: r[4]
                        }
                    });
                });
                
                statistics.success++;
            } catch (e) {
                this.logger.error(`Lỗi dòng Lead (Phone: ${r[4]}): ${e.message}`);
                statistics.failed++;
            }
        }
        this.logger.log(`✅ Migration Leads xong: ${statistics.success} tạo mới, ${statistics.failed} lỗi.`);
        return statistics;
    }

    async synthesizeContracts() {
        this.logger.log(`🚀 Bắt đầu tổng hợp Hợp đồng (Contracts) từ dữ liệu Clients...`);
        let statistics = { success: 0, failed: 0, existing: 0 };

        try {
            const orgs = await this.db.query.organizations.findMany();
            this.logger.log(`Tìm thấy ${orgs.length} Organizations để đối chiếu nội dung Hợp đồng.`);

            for (const org of orgs) {
                const meta: any = org.metadata || {};
                
                // Tiêu chí để có một Hợp đồng hợp lệ
                if (!meta.contractNo && !meta.feeType && !meta.expectedFee) {
                    continue; // Tổ chức này không có data hợp đồng rõ ràng
                }

                const contractNumber = meta.contractNo?.trim() || `HD-STAX-AUTO-${org.id}`;
                
                // Parse giá trị tiền (remove commas/dots/VND)
                let contractValue = 0;
                if (meta.expectedFee) {
                    const cleanStr = meta.expectedFee.toString().replace(/[^0-9]/g, '');
                    if (cleanStr) contractValue = parseFloat(cleanStr);
                }

                // Parse Type & Status
                const cType = (meta.feeType && meta.feeType.toLowerCase().includes('one')) ? 'ONE_OFF' : 'RETAINER';
                let cStatus: 'DRAFT' | 'PENDING_SIGN' | 'ACTIVE' | 'EXPIRING_SOON' | 'EXPIRED' | 'CANCELLED' = 'ACTIVE';
                if (org.status === 'INACTIVE' || org.status === 'CHURNED') cStatus = 'CANCELLED';

                await this.db.transaction(async (tx) => {
                    // Check duplicate
                    const existing = await tx.query.contracts.findFirst({
                        where: eq(schema.contracts.contract_number, contractNumber)
                    });
                    
                    if (existing) {
                        statistics.existing++;
                        return;
                    }

                    await tx.insert(schema.contracts).values({
                        organization_id: org.id as number,
                        contract_number: contractNumber,
                        title: `Hợp đồng cung cấp dịch vụ - ${org.company_name}`.substring(0, 255),
                        description: meta.serviceDesc || 'Dịch vụ kế toán luật tổng hợp',
                        contract_type: cType,
                        status: cStatus,
                        value: contractValue > 0 ? contractValue.toString() : null,
                        metadata: {
                            legacy_sign_date: meta.contractSignDate,
                            source: 'SYNTHESIZED_FROM_CLIENT_DATA',
                            suspend_deadline: meta.suspendDeadline
                        }
                    });
                    statistics.success++;
                });
            }
        } catch (e) {
            this.logger.error(`Lỗi quá trình tổng hợp HĐ: ${e.message}`);
        }

        this.logger.log(`✅ Tổng hợp Contracts xong: ${statistics.success} tạo mới, ${statistics.existing} trùng lặp, ${statistics.failed} lỗi.`);
        return statistics;
    }

    async migrateFinotes(rawData: any[]) {
        this.logger.log(`🚀 Bắt đầu di cư ${rawData.length} dòng Finotes...`);
        let statistics = { success: 0, failed: 0, existing: 0 };

        // 1. Lấy STAX system employee (ID nhỏ nhất) làm mặc định requested_by
        const allEmployees = await this.db.query.employees.findMany();
        const defaultEmployee = allEmployees.reduce((min, e) => 
            (e.id as number) < (min.id as number) ? e : min, allEmployees[0]);
        
        if (!defaultEmployee) {
            this.logger.error('Không tìm thấy nhân viên nào trong hệ thống! Dừng migration Finotes.');
            return statistics;
        }
        this.logger.log(`Dùng nhân viên mặc định: ${defaultEmployee.full_name} (ID: ${defaultEmployee.id})`);

        // 2. Group các dòng theo Số FN (col index 3)
        const fnGroups = new Map<string, any[]>();
        for (const r of rawData) {
            const fnCode = r[3]?.trim();
            if (!fnCode) continue;
            if (!fnGroups.has(fnCode)) fnGroups.set(fnCode, []);
            fnGroups.get(fnCode)!.push(r);
        }
        this.logger.log(`Đã nhóm thành ${fnGroups.size} nhóm Finotes riêng biệt.`);

        // 3. Xử lý từng nhóm FN
        for (const [fnCode, rows] of fnGroups) {
            try {
                const firstRow = rows[0];
                const taxCode = firstRow[1]?.trim();
                const companyName = firstRow[2]?.trim();
                const fnDateStr = firstRow[4]?.trim();
                
                // Parse ngày (format: DD/MM/YYYY)
                let fnDate = new Date();
                if (fnDateStr) {
                    const [d, m, y] = fnDateStr.split('/');
                    if (d && m && y) fnDate = new Date(`${y}-${m.padStart(2,'0')}-${d.padStart(2,'0')}`);
                }

                // Parse status từ cột 12 (Tình trạng thanh toán)
                const rawPayStatus = firstRow[12]?.trim() || '';
                let fnStatus: 'PENDING' | 'PAID' | 'PARTIALLY_PAID' | 'CANCELLED' = 'PENDING';
                if (rawPayStatus.includes('Đã thanh toán')) fnStatus = 'PAID';
                else if (rawPayStatus.includes('Thanh toán từng phần')) fnStatus = 'PARTIALLY_PAID';
                else if (rawPayStatus.includes('FN Hủy')) fnStatus = 'CANCELLED';

                // Tổng hợp tất cả items trong nhóm
                const items = rows.map(r => {
                    const cleanNum = (s: string) => parseFloat(s?.replace(/[^0-9.]/g, '') || '0') || 0;
                    const amount = cleanNum(r[9]);
                    const vat = cleanNum(r[10]);
                    const total = cleanNum(r[11]);
                    return {
                        description: r[8]?.trim() || 'Dịch vụ',
                        amount: amount.toString(),
                        vat_rate: amount > 0 && vat > 0 ? Math.round(vat / amount * 100) : 0,
                        vat_amount: vat.toString(),
                        total_amount: (total || amount + vat).toString(),
                    };
                }).filter(item => parseFloat(item.total_amount) > 0);

                if (items.length === 0) {
                    this.logger.warn(`Bỏ qua FN ${fnCode} — tất cả items có tổng = 0 (FN Hủy?).`);
                    continue;
                }

                const totalAmount = items.reduce((acc, i) => acc + parseFloat(i.total_amount), 0);
                const totalVat = items.reduce((acc, i) => acc + parseFloat(i.vat_amount), 0);
                const serviceType = firstRow[7]?.trim() || 'Dịch vụ kế toán';

                await this.db.transaction(async (tx) => {
                    // Check duplicate
                    const existing = await tx.query.finotes.findFirst({
                        where: eq(schema.finotes.code, fnCode)
                    });
                    if (existing) {
                        statistics.existing++;
                        return;
                    }

                    // Match Organization by MST
                    let orgId: number | null = null;
                    if (taxCode && taxCode.length > 5) {
                        const org = await tx.query.organizations.findFirst({
                            where: eq(schema.organizations.tax_code, taxCode)
                        });
                        if (org) orgId = org.id as number;
                    }
                    if (!orgId && companyName) {
                        const org = await tx.query.organizations.findFirst({
                            where: eq(schema.organizations.company_name, companyName)
                        });
                        if (org) orgId = org.id as number;
                    }

                    // Insert Finote header
                    const [newFinote] = await tx.insert(schema.finotes).values({
                        code: fnCode,
                        type: 'INCOME',
                        source_org_id: orgId,
                        requested_by_id: defaultEmployee.id as number,
                        title: `${serviceType} - ${companyName || 'Khách hàng'}`.substring(0, 255),
                        total_amount: totalAmount.toString(),
                        total_vat: totalVat.toString(),
                        category: serviceType,
                        status: fnStatus,
                        deadline_at: fnDate,
                        paid_at: fnStatus === 'PAID' ? fnDate : null,
                    }).returning({ id: schema.finotes.id });

                    // Insert Finote Items
                    if (items.length > 0) {
                        await tx.insert(schema.finoteItems).values(
                            items.map(item => ({ finote_id: newFinote.id as number, ...item }))
                        );
                    }
                    statistics.success++;
                });
            } catch (e) {
                this.logger.error(`Lỗi FN ${fnCode}: ${e.message}`);
                statistics.failed++;
            }
        }

        this.logger.log(`✅ Migration Finotes xong: ${statistics.success} tạo mới, ${statistics.existing} trùng lặp, ${statistics.failed} lỗi.`);
        return statistics;
    }
}
