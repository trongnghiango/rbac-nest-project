import { Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import type { IUserRepository } from '../../../user/domain/repositories/user-repository.interface';
import { JwtPayload } from '../../../shared/types/common.types';
declare const JwtStrategy_base: new (...args: [opt: import("passport-jwt").StrategyOptionsWithRequest] | [opt: import("passport-jwt").StrategyOptionsWithoutRequest]) => Strategy & {
    validate(...args: any[]): unknown;
};
export declare class JwtStrategy extends JwtStrategy_base {
    private configService;
    private userRepository;
    constructor(configService: ConfigService, userRepository: IUserRepository);
    validate(payload: JwtPayload): Promise<{
        id: number;
        username: string;
        email: string | undefined;
        fullName: string;
        roles: string[];
    } | null>;
}
export {};
