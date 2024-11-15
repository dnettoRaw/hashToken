import * as crypto from 'crypto';

// Classe que gerencia a geração e validação de tokens seguros
export default class AdvancedTokenManager {
    private algorithm: string; // Algoritmo de hash utilizado (ex: sha256)
    private secret: string; // Chave secreta usada para gerar o checksum
    private salts: string[]; // Tabela de salts para adicionar entropia aos tokens
    private lastSaltIndex: number | null = null; // Armazena o último índice de salt usado para evitar repetições

    // Construtor que inicializa a classe com secret e salts, permitindo geração automática caso permitida
    constructor(secret?: string, salts?: string[], algorithm: string = 'sha256', allowAutoGenerate: boolean = true) {
        // Verifica se a secret foi fornecida, caso contrário, gera automaticamente se permitido
        if (!secret) {
            if (allowAutoGenerate) {
                this.secret = this.generateRandomKey(32); // Gera uma chave secreta aleatória de 32 caracteres
                console.warn(
                    "⚠️ Uma secret foi gerada automaticamente. Certifique-se de salvá-la em um local seguro, como um arquivo .env."
                );
            } else {
                throw new Error("A chave secreta deve ter pelo menos 16 caracteres.");
            }
        } else if (secret.length < 16) {
            throw new Error("A chave secreta deve ter pelo menos 16 caracteres.");
        } else {
            this.secret = secret; // Usa a secret fornecida
        }
    
        // Verifica se os salts foram fornecidos, caso contrário, gera automaticamente se permitido
        if (!salts || salts.length < 2) {
            if (allowAutoGenerate) {
                this.salts = Array.from({ length: 10 }, () => this.generateRandomKey(16)); // Gera 10 salts aleatórios
                console.warn(
                    "⚠️ Uma tabela de salts foi gerada automaticamente. Certifique-se de salvá-la em um local seguro, como um arquivo .env."
                );
            } else {
                throw new Error("A tabela de salts não pode estar vazia.");
            }
        } else {
            this.salts = salts; // Usa os salts fornecidos
        }
    
        this.algorithm = algorithm; // Define o algoritmo de hash (padrão: sha256)
    }

    // Gera uma chave aleatória com o número de caracteres especificado
    private generateRandomKey(length: number): string {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; // Pool de caracteres
        return Array.from({ length }, () =>
            characters.charAt(Math.floor(Math.random() * characters.length))
        ).join(''); // Retorna a chave gerada
    }

    // Obtém um índice de salt aleatório, garantindo que não seja igual ao último usado
    private getRandomSaltIndex(): number {
        let index: number;
        do {
            index = Math.floor(Math.random() * this.salts.length); // Gera um índice aleatório
        } while (index === this.lastSaltIndex); // Garante que não repita o último índice
        this.lastSaltIndex = index; // Armazena o índice atual como último usado
        return index;
    }

    private validateSaltIndex(index: number): number {
        if (index < 0 || index >= this.salts.length) {
            throw new Error(`Índice de salt inválido: ${index}. Deve estar entre 0 e ${this.salts.length - 1}.`);
        }
        return index;
    }

    // Gera um token seguro para o dado de entrada
    public generateToken(input: string, forcedSaltIndex?: number): string {
        const saltIndex = forcedSaltIndex !== undefined ? this.validateSaltIndex(forcedSaltIndex) : this.getRandomSaltIndex();; // Obtém um índice de salt aleatório ou usa o passado para a funcao
        const salt = this.salts[saltIndex]; // Seleciona o salt correspondente
        const checksum = this.createChecksum(input, salt); // Calcula o checksum para o dado de entrada
        const combinedData = `${input}|${saltIndex}|${checksum}`; // Combina os dados, índice do salt e checksum
        return Buffer.from(combinedData).toString('base64'); // Retorna o token codificado em Base64
    }

    // Valida um token e retorna os dados originais se válido
    public validateToken(token: string): string | null {
        try {
            const decoded = Buffer.from(token, 'base64').toString('utf-8'); // Decodifica o token de Base64
            const [input, saltIndexStr, checksum] = decoded.split('|'); // Divide os componentes do token
            const saltIndex = parseInt(saltIndexStr, 10); // Converte o índice do salt para número

            // Verifica se o índice do salt é válido
            if (isNaN(saltIndex) || saltIndex < 0 || saltIndex >= this.salts.length) {
                console.error("Índice de salt inválido!"); // Loga erro se inválido
                return null;
            }

            const salt = this.salts[saltIndex]; // Obtém o salt correspondente
            const validChecksum = this.createChecksum(input, salt); // Recalcula o checksum

            // Compara o checksum recalculado com o checksum original
            return validChecksum === checksum ? input : null; // Retorna os dados originais se válido
        } catch (error) {
            console.error("Erro ao validar o token:", error); // Loga qualquer erro durante a validação
            return null;
        }
    }

    // Calcula o checksum combinando os dados de entrada e o salt
    private createChecksum(input: string, salt: string): string {
        const hash = crypto.createHmac(this.algorithm, this.secret); // Cria um hash HMAC com o algoritmo e a secret
        hash.update(input + salt); // Atualiza o hash com os dados combinados
        return hash.digest('hex'); // Retorna o checksum em formato hexadecimal
    }

    // Extrai os dados originais de um token válido
    public extractOriginalData(token: string): string | null {
        return this.validateToken(token); // Valida o token e retorna os dados originais se válido
    }

    // Retorna a configuração atual (secret e salts) para salvar em ambiente seguro
    public getConfig(): { secret: string; salts: string[] } {
        return { secret: this.secret, salts: this.salts }; // Retorna a chave secreta e a tabela de salts
    }
}