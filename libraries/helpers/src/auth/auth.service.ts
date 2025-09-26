import { sign, verify } from 'jsonwebtoken';
import { hashSync, compareSync } from 'bcrypt';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

export class AuthService {
  private static cryptoParams: { key: Buffer; iv: Buffer };

  static hashPassword(password: string) {
    return hashSync(password, 10);
  }
  static comparePassword(password: string, hash: string) {
    return compareSync(password, hash);
  }
  static signJWT(value: object) {
    return sign(value, process.env.JWT_SECRET!);
  }
  static verifyJWT(token: string) {
    return verify(token, process.env.JWT_SECRET!);
  }

  static fixedEncryption(value: string) {
    // encryption algorithm
    const algorithm = 'aes-256-cbc';
    const { key, iv } = this.getCryptoParams();
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    // encrypt the plain text
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return encrypted;
  }

  static fixedDecryption(hash: string) {
    const algorithm = 'aes-256-cbc';
    const { key, iv } = this.getCryptoParams();
    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    // decrypt the encrypted text
    let decrypted = decipher.update(hash, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  private static getCryptoParams() {
    if (!this.cryptoParams) {
      const secret = process.env.JWT_SECRET ?? '';
      if (!secret) {
        throw new Error('JWT_SECRET is not defined');
      }

      const keyLen = 32;
      const ivLen = 16;
      const totalLen = keyLen + ivLen;
      const derived = Buffer.alloc(totalLen);
      const secretBuffer = Buffer.from(secret, 'utf8');
      let previous = Buffer.alloc(0);
      let offset = 0;

      // Replicates OpenSSL EVP_BytesToKey(password, md5, no salt)
      while (offset < totalLen) {
        const hash = crypto.createHash('md5');
        hash.update(previous);
        hash.update(secretBuffer);
        previous = hash.digest();
        previous.copy(derived, offset);
        offset += previous.length;
      }

      this.cryptoParams = {
        key: derived.subarray(0, keyLen),
        iv: derived.subarray(keyLen, totalLen),
      };
    }

    return this.cryptoParams;
  }
}
