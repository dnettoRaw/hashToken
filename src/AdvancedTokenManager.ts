import * as crypto from 'crypto';
import { signJwt, verifyJwt, SignJwtOptions, VerifyJwtOptions, JwtPayload, VerifyJwtResult } from './jwt';

//=======================================//
// editable zone 
const DEFAULT_SECRET_LENGTH = 32;
const DEFAULT_SALT_COUNT = 10;
const DEFAULT_SALT_LENGTH = 16;
const MIN_SECRET_LENGTH = 16;
const MIN_SALT_COUNT = 2;
//=======================================//

export default class AdvancedTokenManager {
    private algorithm: string;
    private secret: string;
    private salts: string[];
    private lastSaltIndex: number | null = null;

    constructor(
        secret?: string,
        salts?: string[],
        algorithm: string = 'sha256',
        allowAutoGenerate: boolean = true,
        noEnv: boolean = false
    ) {
        this.secret = this.initializeSecret(secret, allowAutoGenerate, noEnv);
        this.salts = this.initializeSalts(salts, allowAutoGenerate, noEnv);
        this.algorithm = algorithm;
    }

    private initializeSecret(secret?: string, allowAutoGenerate?: boolean, noEnv?: boolean): string {
        if (!noEnv) {
            secret = secret || process.env.TOKEN_SECRET;
        }
        if (!secret) {
            if (allowAutoGenerate) {
                const generatedSecret = this.generateRandomKey(DEFAULT_SECRET_LENGTH);
                console.warn("⚠️ Secret generated automatically. Store it securely.");
                return generatedSecret;
            }
            throw new Error(`Secret must be at least ${MIN_SECRET_LENGTH} characters long.`);
        }
        if (secret.length < MIN_SECRET_LENGTH) {
            throw new Error(`Secret must be at least ${MIN_SECRET_LENGTH} characters long.`);
        }
        return secret;
    }

    private initializeSalts(salts?: string[], allowAutoGenerate?: boolean,  noEnv?: boolean): string[] {
        if (!noEnv){
            salts = salts || process.env.TOKEN_SALTS?.split(',');
        }
        if (!salts || salts.length < MIN_SALT_COUNT) {
            if (allowAutoGenerate) {
                const generatedSalts = Array.from({ length: DEFAULT_SALT_COUNT }, () => this.generateRandomKey(DEFAULT_SALT_LENGTH));
                console.warn("⚠️ Salts generated automatically. Store them securely.");
                return generatedSalts;
            }
            throw new Error("Salt array cannot be empty or less than 2.");
        }
        if (salts.some(salt => typeof salt !== 'string' || salt.trim() === '')) {
            throw new Error("All salts must be non-empty strings.");
        }
        return salts;
    }

    private generateRandomKey(length: number): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    const randomValues = crypto.randomBytes(length);
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters[randomValues[i] % charactersLength];
    }
    return result;
    }
    

    private getRandomSaltIndex(): number {
        let index: number;
        do {
            index = Math.floor(Math.random() * this.salts.length);
        } while (index === this.lastSaltIndex);
        this.lastSaltIndex = index;
        return index;
    }

    public generateToken(input: string, saltIndex?: number): string {
        const index = saltIndex ?? this.getRandomSaltIndex();
        this.validateSaltIndex(index);
        const salt = this.salts[index];
        const checksum = this.createChecksum(input, salt);
        return Buffer.from(`${input}|${index}|${checksum}`).toString('base64');
    }

    public validateToken(token: string): string | null {
        try {
            const decoded = Buffer.from(token, 'base64').toString('utf-8');
            const [input, saltIndexStr, checksum] = decoded.split('|');
            const saltIndex = parseInt(saltIndexStr, 10);
            this.validateSaltIndex(saltIndex);
            const validChecksum = this.createChecksum(input, this.salts[saltIndex]);
            return validChecksum === checksum ? input : null;
        } catch (error) {
            console.error("Error validating token:", error);
            return null;
        }
    }

    private validateSaltIndex(index: number): void {
        if (index < 0 || index >= this.salts.length) {
            throw new Error(`Invalid salt index: ${index}`);
        }
    }

    private createChecksum(input: string, salt: string): string {
        return crypto.createHmac(this.algorithm, this.secret).update(input + salt).digest('hex');
    }

    public extractData(token: string): string | null {
        return this.validateToken(token);
    }

    public getConfig(): { secret: string; salts: string[] } {
        return { secret: this.secret, salts: this.salts };
    }

    public generateJwt<T extends JwtPayload>(payload: T, options?: SignJwtOptions): string {
        return signJwt(payload, this.secret, options);
    }

    public validateJwt<T extends JwtPayload = JwtPayload>(token: string, options?: VerifyJwtOptions): VerifyJwtResult<T> {
        return verifyJwt<T>(token, this.secret, options);
    }
}