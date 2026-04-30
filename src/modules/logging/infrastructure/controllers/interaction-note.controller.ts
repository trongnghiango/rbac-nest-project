import { Controller, Post, Get, Body, Param, Inject, ParseIntPipe, BadRequestException } from '@nestjs/common';
import { INTERACTION_NOTE_PORT, IInteractionNoteService } from '@core/shared/application/ports/interaction-note.port';
import { ApiTags, ApiOperation, ApiBody } from '@nestjs/swagger';
import { CreateInteractionNoteDto } from '../dtos/create-interaction-note.dto';

@ApiTags('Logging & Activities')
@Controller('organizations/:orgId/notes')
export class InteractionNoteController {
    constructor(
        @Inject(INTERACTION_NOTE_PORT) private readonly noteService: IInteractionNoteService
    ) {}

    @Post()
    @ApiOperation({ summary: 'Thêm ghi chú tương tác thủ công cho doanh nghiệp' })
    @ApiBody({ type: CreateInteractionNoteDto })
    async createNote(
        @Param('orgId', ParseIntPipe) orgId: number,
        @Body() dto: CreateInteractionNoteDto
    ) {
        if (!dto || !dto.content) {
            throw new BadRequestException('Content is required');
        }
        return this.noteService.create({
            organizationId: orgId,
            content: dto.content,
            type: dto.type,
            metadata: dto.metadata,
        });
    }

    @Get()
    @ApiOperation({ summary: 'Lấy danh sách các ghi chú của doanh nghiệp' })
    async getNotes(@Param('orgId', ParseIntPipe) orgId: number) {
        return this.noteService.findByOrganization(orgId);
    }
}
