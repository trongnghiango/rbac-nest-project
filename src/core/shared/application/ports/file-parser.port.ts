export const IFileParser = Symbol('IFileParser');

export interface IFileParser {
  parseCsv<T>(content: string): T[];
}
