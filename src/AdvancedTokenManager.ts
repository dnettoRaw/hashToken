import * as crypto from 'crypto';

export default class AdvancedTokenManager {
    private algorithm: string;
    private secret: string;
    private salts: string[];

    constructor(secret: string, salts: string[], algorithm: string = 'sha256') {
        if (!secret || secret.length < 16) {
            throw new Error("A chave secreta deve ter pelo menos 16 caracteres.");
        }
        if (!salts || salts.length === 0) {
            throw new Error("A tabela de salts não pode estar vazia.");
        }
        this.algorithm = algorithm;
        this.secret = secret;
        this.salts = salts;
    }

    public generateToken(input: string): string {
        const saltIndex = Math.floor(Math.random() * this.salts.length);
        const salt = this.salts[saltIndex];
        const checksum = this.createChecksum(input, salt);
        const combinedData = `${input}|${saltIndex}|${checksum}`;
        return Buffer.from(combinedData).toString('base64');
    }

    public validateToken(token: string): string | null {
        try {
            const decoded = Buffer.from(token, 'base64').toString('utf-8');
            const [input, saltIndexStr, checksum] = decoded.split('|');
            const saltIndex = parseInt(saltIndexStr, 10);

            if (isNaN(saltIndex) || saltIndex < 0 || saltIndex >= this.salts.length) {
                console.error("Índice de salt inválido!");
                return null;
            }

            const salt = this.salts[saltIndex];
            const validChecksum = this.createChecksum(input, salt);

            return validChecksum === checksum ? input : null;
        } catch (error) {
            console.error("Erro ao validar o token:", error);
            return null;
        }
    }

    private createChecksum(input: string, salt: string): string {
        const hash = crypto.createHmac(this.algorithm, this.secret);
        hash.update(input + salt);
        return hash.digest('hex');
    }

    public extractOriginalData(token: string): string | null {
        const validatedData = this.validateToken(token);
        return validatedData;
    }
}
