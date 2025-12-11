export interface IFileParser {
  parseCsv<T>(content: string): T[];
}
