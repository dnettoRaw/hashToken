import * as crypto from 'crypto';

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
        noEnv: boolean = false // Flag para ignorar variáveis de ambiente
    ) {
        // Usa variáveis de ambiente apenas se `noEnv` for false e os valores não forem passados como parâmetro
        if (!noEnv) {
            secret = secret || process.env.TOKEN_SECRET || undefined;
            salts = salts || process.env.TOKEN_SALTS?.split(',') || undefined;
        }
    
        // Validação e inicialização da secret
        if (!secret) {
            if (allowAutoGenerate) {
                this.secret = this.generateRandomKey(32); // Gera uma secret automaticamente
                console.warn(
                    "⚠️ Uma secret foi gerada automaticamente. Certifique-se de salvá-la em um local seguro, como um arquivo .env."
                );
            } else {
                throw new Error("A chave secreta deve ter pelo menos 16 caracteres.");
            }
        } else if (secret.length < 16) {
            throw new Error("A chave secreta deve ter pelo menos 16 caracteres.");
        } else {
            this.secret = secret;
        }
    
        // Validação e inicialização dos salts
        if (!salts || salts.length < 2) {
            if (allowAutoGenerate) {
                this.salts = Array.from({ length: 10 }, () => this.generateRandomKey(16)); // Gera 10 salts automaticamente
                console.warn(
                    "⚠️ Uma tabela de salts foi gerada automaticamente. Certifique-se de salvá-la em um local seguro, como um arquivo .env."
                );
            } else {
                throw new Error("A tabela de salts não pode estar vazia.");
            }
        } else {
            this.salts = salts;
        }
    
        // Validação final dos salts para garantir que eles são strings válidas
        if (this.salts.some(salt => typeof salt !== 'string' || salt.trim() === '')) {
            throw new Error("Todos os salts devem ser strings não vazias.");
        }
    
        // Configuração do algoritmo de hash
        this.algorithm = algorithm;
    }

    // Gera uma chave aleatória com o comprimento especificado
    private generateRandomKey(length: number): string {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        return Array.from({ length }, () =>
            characters.charAt(Math.floor(Math.random() * characters.length))
        ).join('');
    }

    // Retorna um índice de salt aleatório, garantindo que não seja repetido consecutivamente
    private getRandomSaltIndex(): number {
        let index: number;
        do {
            index = Math.floor(Math.random() * this.salts.length);
        } while (index === this.lastSaltIndex);
        this.lastSaltIndex = index;
        return index;
    }

    // Gera um token a partir de uma string de entrada
    public generateToken(input: string, saltIndex?: number): string {
        const index = saltIndex !== undefined ? saltIndex : this.getRandomSaltIndex();
        if (index < 0 || index >= this.salts.length) {
            throw new Error(`Índice de salt inválido: ${index}`);
        }

        const salt = this.salts[index];
        const checksum = this.createChecksum(input, salt);
        const combinedData = `${input}|${index}|${checksum}`;
        return Buffer.from(combinedData).toString('base64');
    }

    // Valida um token e retorna os dados originais se for válido
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

    // Cria um checksum para validar integridade dos dados
    private createChecksum(input: string, salt: string): string {
        const hash = crypto.createHmac(this.algorithm, this.secret);
        hash.update(input + salt);
        return hash.digest('hex');
    }

    // Retorna os dados originais de um token
    public extractOriginalData(token: string): string | null {
        return this.validateToken(token);
    }

    // Retorna a configuração atual de secret e salts
    public getConfig(): { secret: string; salts: string[] } {
        return { secret: this.secret, salts: this.salts };
    }
}
