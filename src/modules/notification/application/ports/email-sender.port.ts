export const IEmailSender = Symbol('IEmailSender');

export interface IEmailSender {
  send(to: string, subject: string, body: string): Promise<boolean>;
}
