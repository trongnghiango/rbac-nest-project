import { Controller, Post, Body, Param, Get, Inject, ParseIntPipe } from '@nestjs/common';
import { INTERACTION_NOTE_PORT, IInteractionNoteService } from '@core/shared/application/ports/interaction-note.port';
import { ApiTags, ApiOperation } from '@nestjs/swagger';

@ApiTags('Logging & Activities')
@Controller('organizations/:orgId/notes')
export class InteractionNoteController {
    constructor(
        @Inject(INTERACTION_NOTE_PORT) private readonly noteService: IInteractionNoteService
    ) {}

    @Post()
    @ApiOperation({ summary: 'Thêm ghi chú tương tác thủ công cho doanh nghiệp' })
    async createNote(
        @Param('orgId', ParseIntPipe) orgId: number,
        @Body() body: { content: string, type?: string, metadata?: any }
    ) {
        return this.noteService.create({
            organization_id: orgId,
            content: body.content,
            type: body.type,
            metadata: body.metadata,
        });
    }

    @Get()
    @ApiOperation({ summary: 'Lấy danh sách các ghi chú của doanh nghiệp' })
    async getNotes(@Param('orgId', ParseIntPipe) orgId: number) {
        return this.noteService.findByOrganization(orgId);
    }
}
