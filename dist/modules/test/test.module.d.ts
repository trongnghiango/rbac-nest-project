import { OnModuleInit } from '@nestjs/common';
import { DatabaseSeeder } from './seeders/database.seeder';
export declare class TestModule implements OnModuleInit {
    private databaseSeeder;
    constructor(databaseSeeder: DatabaseSeeder);
    onModuleInit(): Promise<void>;
}
