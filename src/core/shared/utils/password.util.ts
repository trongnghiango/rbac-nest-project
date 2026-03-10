import * as bcrypt from 'bcrypt';
export class PasswordUtil {
  static async hash(p: string) {
    const salt = await bcrypt.genSalt(10);
    return bcrypt.hash(p, salt);
  }
  static async compare(p: string, h: string) {
    return bcrypt.compare(p, h);
  }
  static validateStrength(p: string) {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/.test(p);
  }
}
