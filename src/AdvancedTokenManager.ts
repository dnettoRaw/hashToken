import * as crypto from 'crypto';
import { signJwt, verifyJwt, SignJwtOptions, VerifyJwtOptions, JwtAlgorithm } from './jwt';

type ManagerSignJwtOptions = Omit<SignJwtOptions, 'secret'> & { secret?: string };
type ManagerVerifyJwtOptions = Omit<VerifyJwtOptions, 'secret'> & { secret?: string };

//=======================================//
// editable zone 
const DEFAULT_SECRET_LENGTH = 32;
const DEFAULT_SALT_COUNT = 10;
const DEFAULT_SALT_LENGTH = 16;
const MIN_SECRET_LENGTH = 16;
const MIN_SALT_COUNT = 2;
//=======================================//

type AdvancedTokenManagerLoggerInput = Partial<Pick<Console, 'warn' | 'error'>>;

interface AdvancedTokenManagerLogger {
    warn: (message: string) => void;
    error: (message: string) => void;
}

export interface AdvancedTokenManagerOptions {
    logger?: AdvancedTokenManagerLoggerInput;
    jwtDefaultAlgorithms?: JwtAlgorithm[];
    defaultSecretLength?: number;
    defaultSaltCount?: number;
    defaultSaltLength?: number;
    throwOnValidationFailure?: boolean;
    jwtMaxPayloadSize?: number;
    jwtAllowedClaims?: string[];
}

export default class AdvancedTokenManager {
    private algorithm: string;
    private secret: string;
    private salts: string[];
    private lastSaltIndex: number | null = null;
    private readonly logger: AdvancedTokenManagerLogger;
    private readonly jwtDefaultAlgorithms?: JwtAlgorithm[];
    private readonly defaultSecretLength: number;
    private readonly defaultSaltCount: number;
    private readonly defaultSaltLength: number;
    private readonly throwOnValidationFailure: boolean;
    private readonly jwtMaxPayloadSize?: number;
    private readonly jwtAllowedClaims?: string[];

    constructor(
        secret?: string,
        salts?: string[],
        algorithm: string = 'sha256',
        allowAutoGenerate: boolean = true,
        noEnv: boolean = false,
        options: AdvancedTokenManagerOptions = {}
    ) {
        this.logger = this.resolveLogger(options.logger);
        this.defaultSecretLength = this.resolveLengthOption(
            'defaultSecretLength',
            options.defaultSecretLength,
            DEFAULT_SECRET_LENGTH,
            MIN_SECRET_LENGTH
        );
        this.defaultSaltCount = this.resolveLengthOption(
            'defaultSaltCount',
            options.defaultSaltCount,
            DEFAULT_SALT_COUNT,
            MIN_SALT_COUNT
        );
        this.defaultSaltLength = this.resolveLengthOption(
            'defaultSaltLength',
            options.defaultSaltLength,
            DEFAULT_SALT_LENGTH,
            1
        );
        this.jwtDefaultAlgorithms = this.normalizeAlgorithms(options.jwtDefaultAlgorithms);
        this.throwOnValidationFailure = options.throwOnValidationFailure ?? false;
        this.jwtMaxPayloadSize = this.resolvePositiveNumberOption('jwtMaxPayloadSize', options.jwtMaxPayloadSize);
        this.jwtAllowedClaims = this.normalizeAllowedClaims(options.jwtAllowedClaims);

        this.secret = this.initializeSecret(secret, allowAutoGenerate, noEnv);
        this.salts = this.initializeSalts(salts, allowAutoGenerate, noEnv);
        this.algorithm = algorithm;
    }

    private resolveLogger(logger?: AdvancedTokenManagerLoggerInput): AdvancedTokenManagerLogger {
        const warn = logger?.warn ? logger.warn.bind(logger) : console.warn.bind(console);
        const error = logger?.error ? logger.error.bind(logger) : console.error.bind(console);
        return {
            warn,
            error: typeof error === 'function' ? error : warn
        };
    }

    private resolveLengthOption(
        name: string,
        provided: number | undefined,
        fallback: number,
        minimum: number
    ): number {
        if (provided === undefined) {
            return fallback;
        }
        if (!Number.isInteger(provided) || provided < minimum) {
            throw new Error(`${name} must be an integer greater than or equal to ${minimum}.`);
        }
        return provided;
    }

    private resolvePositiveNumberOption(name: string, value?: number): number | undefined {
        if (value === undefined) {
            return undefined;
        }
        if (!Number.isFinite(value) || value <= 0) {
            throw new Error(`${name} must be a positive number.`);
        }
        return Math.floor(value);
    }

    private normalizeAlgorithms(algorithms?: JwtAlgorithm[]): JwtAlgorithm[] | undefined {
        if (algorithms === undefined) {
            return undefined;
        }
        if (!Array.isArray(algorithms) || algorithms.length === 0) {
            throw new Error('jwtDefaultAlgorithms must be a non-empty array when provided.');
        }
        const unique: JwtAlgorithm[] = [];
        for (const algorithm of algorithms) {
            if (algorithm !== 'HS256' && algorithm !== 'HS512') {
                throw new Error(`Unsupported JWT algorithm in configuration: ${algorithm}`);
            }
            if (!unique.includes(algorithm)) {
                unique.push(algorithm);
            }
        }
        return unique;
    }

    private normalizeAllowedClaims(claims?: string[]): string[] | undefined {
        if (claims === undefined) {
            return undefined;
        }
        if (!Array.isArray(claims)) {
            throw new Error('jwtAllowedClaims must be an array of non-empty strings.');
        }
        const unique: string[] = [];
        for (const claim of claims) {
            if (typeof claim !== 'string') {
                throw new Error('jwtAllowedClaims must be an array of non-empty strings.');
            }
            const trimmed = claim.trim();
            if (trimmed.length === 0) {
                throw new Error('jwtAllowedClaims must be an array of non-empty strings.');
            }
            if (!unique.includes(trimmed)) {
                unique.push(trimmed);
            }
        }
        return unique;
    }

    private initializeSecret(secret?: string, allowAutoGenerate?: boolean, noEnv?: boolean): string {
        let candidate = secret?.trim();
        if (!noEnv && candidate === undefined) {
            const envSecret = process.env.TOKEN_SECRET;
            candidate = envSecret !== undefined ? envSecret.trim() : undefined;
        }
        if (!candidate) {
            if (allowAutoGenerate) {
                const generatedSecret = this.generateRandomKey(this.defaultSecretLength);
                this.logger.warn('⚠️ Secret generated automatically. Store it securely.');
                return generatedSecret;
            }
            throw new Error(`Secret must be at least ${MIN_SECRET_LENGTH} characters long.`);
        }
        if (candidate.length < MIN_SECRET_LENGTH) {
            throw new Error(`Secret must be at least ${MIN_SECRET_LENGTH} characters long.`);
        }
        return candidate;
    }

    private initializeSalts(salts?: string[], allowAutoGenerate?: boolean,  noEnv?: boolean): string[] {
        let providedSalts = salts;
        if (!noEnv && (!providedSalts || providedSalts.length === 0)) {
            const envSalts = process.env.TOKEN_SALTS;
            if (envSalts) {
                providedSalts = envSalts.split(',');
            }
        }
        if (!providedSalts || providedSalts.length < MIN_SALT_COUNT) {
            if (allowAutoGenerate) {
                const generatedSalts = Array.from({ length: this.defaultSaltCount }, () =>
                    this.generateRandomKey(this.defaultSaltLength)
                );
                this.logger.warn('⚠️ Salts generated automatically. Store them securely.');
                return generatedSalts;
            }
            throw new Error('Salt array cannot be empty or less than 2.');
        }
        const sanitizedSalts = providedSalts.map(salt => {
            if (typeof salt !== 'string') {
                throw new Error('All salts must be non-empty strings.');
            }
            const trimmed = salt.trim();
            if (trimmed.length === 0) {
                throw new Error('All salts must be non-empty strings.');
            }
            return trimmed;
        });
        return sanitizedSalts;
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

    public validateToken(token: string, options?: { throwOnFailure?: boolean }): string | null {
        const shouldThrow = options?.throwOnFailure ?? this.throwOnValidationFailure;
        try {
            const decoded = Buffer.from(token, 'base64').toString('utf-8');
            const [input, saltIndexStr, checksum] = decoded.split('|');
            const saltIndex = parseInt(saltIndexStr, 10);
            this.validateSaltIndex(saltIndex);
            const validChecksum = this.createChecksum(input, this.salts[saltIndex]);
            return validChecksum === checksum ? input : null;
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            this.logger.error(`Error validating token: ${message}`);
            if (shouldThrow) {
                throw error instanceof Error ? error : new Error(message);
            }
            return null;
        }
    }

    private validateSaltIndex(index: number): void {
        if (!Number.isInteger(index) || index < 0 || index >= this.salts.length) {
            throw new Error(`Invalid salt index: ${index}`);
        }
    }

    private createChecksum(input: string, salt: string): string {
        return crypto.createHmac(this.algorithm, this.secret).update(input + salt).digest('hex');
    }

    public extractData(token: string): string | null {
        return this.validateToken(token);
    }

    public generateJwt(payload: Record<string, unknown>, options?: ManagerSignJwtOptions): string {
        const secret = options?.secret?.trim() || this.secret;
        const signOptions: SignJwtOptions = { ...(options || {}), secret };
        return signJwt(payload, signOptions);
    }

    public validateJwt<T extends Record<string, unknown> = Record<string, unknown>>(
        token: string,
        options?: ManagerVerifyJwtOptions
    ): T {
        const secret = options?.secret?.trim() || this.secret;
        const verifyOptions: VerifyJwtOptions = { ...(options || {}), secret };
        if (!verifyOptions.algorithms && this.jwtDefaultAlgorithms) {
            verifyOptions.algorithms = [...this.jwtDefaultAlgorithms];
        }
        if (verifyOptions.maxPayloadSize === undefined && this.jwtMaxPayloadSize !== undefined) {
            verifyOptions.maxPayloadSize = this.jwtMaxPayloadSize;
        }
        if (verifyOptions.allowedClaims === undefined && this.jwtAllowedClaims) {
            verifyOptions.allowedClaims = [...this.jwtAllowedClaims];
        }
        return verifyJwt<T>(token, verifyOptions);
    }

    public getConfig(): { secret: string; salts: string[] } {
        return { secret: this.secret, salts: this.salts };
    }
}
