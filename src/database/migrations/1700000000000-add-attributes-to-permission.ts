import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddAttributesToPermission1700000000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // 1. Lấy thông tin bảng permissions
    const table = await queryRunner.getTable('permissions');

    // 2. Kiểm tra xem cột 'attributes' đã tồn tại chưa
    const attributeColumn = table?.findColumnByName('attributes');

    // 3. Nếu chưa có thì thêm vào
    if (!attributeColumn) {
      await queryRunner.addColumn(
        'permissions',
        new TableColumn({
          name: 'attributes',
          type: 'varchar',
          default: "'*'", // Mặc định là dấu sao (Full quyền)
          isNullable: false,
        }),
      );
      console.log(
        '✅ MIGRATION: Added "attributes" column to "permissions" table.',
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Logic Rollback: Nếu chạy revert thì xóa cột đi
    const table = await queryRunner.getTable('permissions');
    const attributeColumn = table?.findColumnByName('attributes');

    if (attributeColumn) {
      await queryRunner.dropColumn('permissions', 'attributes');
    }
  }
}
