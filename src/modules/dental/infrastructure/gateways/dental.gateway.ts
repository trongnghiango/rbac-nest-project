import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  OnGatewayConnection,
  OnGatewayDisconnect,
  MessageBody,
  ConnectedSocket,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { Logger } from '@nestjs/common';

@WebSocketGateway({
  namespace: 'dental',
  cors: { origin: '*' },
})
export class DentalGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;

  private logger = new Logger(DentalGateway.name);

  handleConnection(client: Socket) {
    this.logger.log(`Client connected: ${client.id}`);
  }

  handleDisconnect(client: Socket) {
    this.logger.log(`Client disconnected: ${client.id}`);
  }

  @SubscribeMessage('join_case')
  handleJoinCase(
    @MessageBody() data: { caseId: string },
    @ConnectedSocket() client: Socket,
  ) {
    const roomName = `case_${data.caseId}`;
    client.join(roomName);
    this.logger.log(`Client ${client.id} joined room: ${roomName}`);
    return { event: 'joined', data: `Joined case ${data.caseId}` };
  }

  notifyProgress(caseId: string, data: any) {
    this.server.to(`case_${caseId}`).emit('conversion_progress', data);
  }

  notifyComplete(caseId: string, data: any) {
    this.server.to(`case_${caseId}`).emit('case_ready', data);
  }
}
