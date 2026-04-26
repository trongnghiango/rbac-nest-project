import { Module } from '@nestjs/common';
import { ClientOnboardedHandler } from './application/handlers/client-onboarded.handler';

@Module({
    providers: [ClientOnboardedHandler],
})
export class OnboardingModule {}
