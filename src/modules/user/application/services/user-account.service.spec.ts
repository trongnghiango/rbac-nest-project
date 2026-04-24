// src/modules/user/application/services/user-account.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { UserAccountService } from './user-account.service';
import { IUserRepository } from '../../domain/repositories/user.repository';
import { UserUniquenessChecker } from '../../domain/services/user-uniqueness.checker';
import { User } from '../../domain/entities/user.entity';
import { ConflictException } from '@nestjs/common';

describe('UserAccountService', () => {
  let service: UserAccountService;
  let userRepository: jest.Mocked<IUserRepository>;
  let uniquenessChecker: jest.Mocked<UserUniquenessChecker>;

  beforeEach(async () => {
    // 1. Tạo các bản giả (Mock) cho các phụ thuộc
    const mockUserRepository = {
      save: jest.fn(),
      findByUsername: jest.fn(),
    };
    const mockUniquenessChecker = {
      checkUniqueOrThrow: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UserAccountService,
        { provide: IUserRepository, useValue: mockUserRepository },
        { provide: UserUniquenessChecker, useValue: mockUniquenessChecker },
      ],
    }).compile();

    service = module.get<UserAccountService>(UserAccountService);
    userRepository = module.get(IUserRepository);
    uniquenessChecker = module.get(UserUniquenessChecker);
  });

  describe('provisionAccount', () => {
    // Kỹ thuật Data-Driven Testing với it.each
    it.each([
      { username: 'trongnghia', email: 'nghia@stax.vn', fullName: 'Trong Nghia' },
      { username: 'admin_erp', email: 'admin@stax.vn', fullName: 'ERP Admin' },
    ])('nên tạo tài khoản thành công cho user: $username', async (input) => {
      // Arrange (Chuẩn bị)
      const mockSavedUser = new User({ ...input, id: 1, roles: [], isActive: true });
      userRepository.save.mockResolvedValue(mockSavedUser);
      uniquenessChecker.checkUniqueOrThrow.mockResolvedValue(undefined);

      // Act (Thực thi)
      const result = await service.provisionAccount(input);

      // Assert (Kiểm tra)
      expect(result).toBeDefined();
      expect(result.username).toBe(input.username);
      expect(uniquenessChecker.checkUniqueOrThrow).toHaveBeenCalledWith(input.username, input.email);
      expect(userRepository.save).toHaveBeenCalled();
    });

    it('nên báo lỗi nếu username đã tồn tại', async () => {
      // Arrange
      uniquenessChecker.checkUniqueOrThrow.mockRejectedValue(new ConflictException('User already exists'));

      // Act & Assert
      await expect(service.provisionAccount({ username: 'existing', email: 'test@stax.vn' }))
        .rejects.toThrow(ConflictException);
    });
  });
});
