const crypto = require("crypto");

class AdvancedTokenManager {
    private algorithm: string; // Algoritmo de hashing (por exemplo, SHA-256)
    private secret: string; // Chave secreta para o HMAC
    private salts: string[]; // Tabela predefinida de salts

    /**
     * Inicializa o Token Manager com uma chave secreta, uma tabela de salts e um algoritmo de hashing.
     * @param {string} secret - Uma chave secreta segura para gerar o checksum (mínimo 16 caracteres).
     * @param {string[]} salts - Um array de salts predefinidos.
     * @param {string} algorithm - O algoritmo de hashing a ser utilizado (padrão: 'sha256').
     */
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

    /**
     * Gera um token seguro contendo a string de entrada, o índice do salt e um checksum.
     * @param {string} input - A string de entrada para gerar o token.
     * @returns {string} - Um token codificado em Base64.
     */
    public generateToken(input: string): string {
        const saltIndex = Math.floor(Math.random() * this.salts.length); // Seleciona um salt aleatório
        const salt = this.salts[saltIndex];
        const checksum = this.createChecksum(input, salt);
        const combinedData = `${input}|${saltIndex}|${checksum}`; // Concatena os dados
        return Buffer.from(combinedData).toString('base64'); // Codifica em Base64
    }

    /**
     * Decodifica e valida um token para garantir sua integridade.
     * @param {string} token - O token codificado em Base64.
     * @returns {string | null} - A string original se válida, ou null se inválida.
     */
    public validateToken(token: string): string | null {
        try {
            const decoded = Buffer.from(token, 'base64').toString('utf-8'); // Decodifica Base64
            const [input, saltIndexStr, checksum] = decoded.split('|');
            const saltIndex = parseInt(saltIndexStr, 10);

            // Verifica se o índice do salt é válido
            if (isNaN(saltIndex) || saltIndex < 0 || saltIndex >= this.salts.length) {
                console.error("Índice de salt inválido!");
                return null;
            }

            const salt = this.salts[saltIndex];
            const validChecksum = this.createChecksum(input, salt);

            // Valida o checksum
            if (validChecksum === checksum) {
                return input;
            } else {
                console.error("Checksum inválido!");
                return null;
            }
        } catch (error) {
            console.error("Erro ao validar o token:", error);
            return null;
        }
    }

    /**
     * Cria um checksum seguro utilizando a string de entrada, um salt e a chave secreta.
     * @param {string} input - A string de entrada para o hashing.
     * @param {string} salt - O salt utilizado na geração do checksum.
     * @returns {string} - O checksum gerado como uma string hexadecimal.
     */
    private createChecksum(input: string, salt: string): string {
        const hash = crypto.createHmac(this.algorithm, this.secret); // Cria o HMAC
        hash.update(input + salt); // Gera o hash da entrada concatenada com o salt
        return hash.digest('hex'); // Retorna o checksum em formato hexadecimal
    }
}

// Exemplo de uso
const secretKey = "minha-chave-secreta-muito-segura"; // Mantenha esta chave segura!
const salts = [
    "salt-um",
    "salt-dois",
    "salt-tres",
    "salt-quatro",
    "salt-cinco",
]; // Tabela de salts predefinidos

const tokenManager = new AdvancedTokenManager(secretKey, salts);

const originalString = "dados-muito-sensitivos";
const token = tokenManager.generateToken(originalString);
console.log("Token gerado:", token);

const validatedString = tokenManager.validateToken(token);
console.log("String validada:", validatedString);

const invalidToken = token.slice(0, -1) + 'x'; // Modificação proposital para simular um token inválido
const invalidValidation = tokenManager.validateToken(invalidToken);
console.log("Validação do token inválido:", invalidValidation);
