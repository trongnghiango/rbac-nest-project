export const IChatbotService = Symbol('IChatbotService');

export interface IChatbotService {
    sendMessage(chatId: string, message: string): Promise<void>;
    sendPhoto(chatId: string, photoUrl: string, caption?: string): Promise<void>;
}
