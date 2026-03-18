import { Injectable, Inject, BadRequestException, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { IOrgStructureRepository } from '@modules/org-structure/domain/repositories/org-structure.repository';
import { IEmployeeRepository } from '../../domain/repositories/employee.repository';
import { CreateEmployeeDto } from '../dtos/create-employee.dto';
import { UserService } from '@modules/user/application/services/user.service';
import { ProvisionAccountDto } from '../dtos/provision-account.dto';

@Injectable()
export class EmployeeService {
    constructor(
        @Inject(IEmployeeRepository) private employeeRepo: IEmployeeRepository,
        // Mượn hàng xóm OrgStructure
        @Inject(IOrgStructureRepository) private orgRepo: IOrgStructureRepository,

        private userService: UserService,
    ) { }

    // =========================================================================
    // HÀM 1: DÀNH CHO NHÂN SỰ (HR) - CHỈ TẠO HỒ SƠ, CHƯA CÓ TÀI KHOẢN
    // =========================================================================
    async onboardNewEmployee(dto: CreateEmployeeDto) {
        // 1. Check vị trí trong sơ đồ tổ chức
        const position = await this.orgRepo.findPositionById(dto.positionId);

        if (!position) {
            throw new BadRequestException('Vị trí bổ nhiệm không tồn tại trong sơ đồ tổ chức.');
        }
        if (!position.isActive) {
            throw new BadRequestException('Vị trí này hiện đang bị đóng băng tuyển dụng.');
        }

        // 2. Lưu dữ liệu hồ sơ nhân viên (Lúc này userId thường là null)
        const newEmployee = await this.employeeRepo.save({
            userId: dto.userId || null,
            employeeCode: dto.employeeCode,
            fullName: dto.fullName,
            locationId: dto.locationId,
            positionId: position.id,
        });

        // Chỉ trả về thông tin nhân viên vừa tạo
        return newEmployee;
    }


    // =========================================================================
    // HÀM 2: DÀNH CHO IT - CẤP TÀI KHOẢN CHO NHÂN VIÊN ĐÃ ĐƯỢC HR TẠO HỒ SƠ
    // =========================================================================
    async provisionUserAccount(employeeId: number, dto: ProvisionAccountDto) {

        // 1. Tìm nhân viên xem có tồn tại không
        const employee = await this.employeeRepo.findById(employeeId);
        if (!employee) throw new NotFoundException('Không tìm thấy hồ sơ nhân viên');

        // 2. Nếu đã có tài khoản rồi thì báo lỗi
        if (employee.userId) throw new BadRequestException('Nhân viên này đã có tài khoản ERP');

        // 3. Chuẩn hóa Username (Lấy từ input hoặc dùng mã nhân viên)
        const rawUsername = dto.username || employee.employeeCode;
        const finalUsername = rawUsername.trim().toLowerCase();

        // 4. Sinh password ngẫu nhiên an toàn
        const defaultPassword = 'Hrm@' + Math.floor(1000 + Math.random() * 9000);

        try {
            // 5. Gọi module User để tạo tài khoản đăng nhập (Identity)
            const newUser = await this.userService.createUser({
                id: undefined as any,
                username: finalUsername,
                password: defaultPassword,
                email: dto.email,
                fullName: employee.fullName,
            });

            // 6. Cập nhật lại hồ sơ nhân viên: Gắn ID của tài khoản vừa tạo vào hồ sơ
            await this.employeeRepo.save({
                id: employeeId,       // CÓ ID -> Repository sẽ hiểu đây là lệnh UPDATE
                userId: newUser.id,   // Gắn userId vào
            });

            // 7. Trả về kết quả cho IT hoặc tự động gửi email cho nhân viên
            return {
                success: true,
                message: 'Đã cấp tài khoản thành công',
                credentials: {
                    username: finalUsername,
                    password: defaultPassword
                }
            };
        } catch (error) {
            if (error.message === 'User already exists') {
                throw new BadRequestException(`Tên đăng nhập '${finalUsername}' đã được sử dụng. Vui lòng chọn tên khác.`);
            }
            throw new InternalServerErrorException('Lỗi hệ thống khi cấp tài khoản');
        }
    }


    async getAllEmployees() {
        return this.employeeRepo.findAll();
    }
}
