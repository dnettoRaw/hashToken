import { describe, test, expect } from '@jest/globals';
import AdvancedTokenManager from '../src/AdvancedTokenManager'; // Ajuste o caminho para a classe

let testCounter = 0; // Contador global para o número do teste
const totalTests = 15; // Atualize com o número total de testes

// Função para exibir o progresso do teste
const logTestProgress = (testName: string) => {
    testCounter++;
    const formattedCounter = String(testCounter).padStart(2, '0');
    // console.log(`${formattedCounter}/${totalTests} - ${testName}`);
};


describe('AdvancedTokenManager', () => {
    const secretKey = 'my-very-secure-key-12345';
    const salts = ['salt-one', 'salt-two', 'salt-three', 'salt-four', 'salt-five'];

    let tokenManager: AdvancedTokenManager;

    // Mock do console.error
    let consoleErrorMock: jest.SpyInstance;

    beforeAll(() => {
        consoleErrorMock = jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterAll(() => {
        consoleErrorMock.mockRestore(); // Restaura o comportamento original após os testes
    });

    beforeEach(() => {
        // Inicializa uma nova instância antes de cada teste
        tokenManager = new AdvancedTokenManager(secretKey, salts);
    });

    test(`${testCounter} should generate a valid token`, () => {
    logTestProgress('should generate a valid token');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        expect(token).toBeDefined();
        expect(typeof token).toBe('string');
    });

    test('should validate a valid token correctly', () => {
    logTestProgress('should validate a valid token correctly');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const validatedInput = tokenManager.validateToken(token);

        expect(validatedInput).toBe(input);
    });

    test('should return null for a modified token', () => {
    logTestProgress('should return null for a modified token');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        // Modifica o token para simular um token inválido
        const invalidToken = token.slice(0, -1) + 'x';
        const validatedInput = tokenManager.validateToken(invalidToken);

        expect(validatedInput).toBeNull();
    });

    test('should return null for a token with an invalid salt index', () => {
    logTestProgress('should return null for a token with an invalid salt index');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        // Modifica o índice do salt no token
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, saltIndex, checksum] = decoded.split('|');
        const invalidSaltIndex = salts.length; // Índice inválido (fora do intervalo)
        const modifiedToken = Buffer.from(`${data}|${invalidSaltIndex}|${checksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(modifiedToken);
        expect(validatedInput).toBeNull();
    });

    test('should generate unique tokens for the same input with different salts', () => {
    logTestProgress('should generate unique tokens for the same input with different salts');
        const input = 'sensitive-data';
        const token1 = tokenManager.generateToken(input);
        const token2 = tokenManager.generateToken(input);

        expect(token1).not.toBe(token2);
    });

    test('should throw an error if initialized with an invalid secret key', () => {
    logTestProgress('should throw an error if initialized with an invalid secret key');
        expect(() => new AdvancedTokenManager('', salts)).toThrowError('A chave secreta deve ter pelo menos 16 caracteres.');
    });

    test('should throw an error if initialized with an empty salt table', () => {
    logTestProgress('should throw an error if initialized with an empty salt table');
        expect(() => new AdvancedTokenManager(secretKey, [])).toThrowError('A tabela de salts não pode estar vazia.');
    });

    // Novos testes adicionados:
    test('should extract the original data from a valid token', () => {
    logTestProgress('should extract the original data from a valid token');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const extractedData = tokenManager.extractOriginalData(token);
    
        expect(extractedData).toBe(input);
    });
    
    test('should return null when extracting data from an invalid token', () => {
    logTestProgress('should return null when extracting data from an invalid token');
        const invalidToken = 'invalid-base64-token';
        const extractedData = tokenManager.extractOriginalData(invalidToken);
    
        expect(extractedData).toBeNull();
    });

    test('should handle an empty input gracefully', () => {
    logTestProgress('should handle an empty input gracefully');
        const input = '';
        const token = tokenManager.generateToken(input);
        const validatedInput = tokenManager.validateToken(token);

        expect(validatedInput).toBe(input); // Valida que o token vazio é tratado corretamente
    });

    test('should return null for an invalid Base64 token', () => {
    logTestProgress('should return null for an invalid Base64 token');
        const invalidToken = 'invalid-base64-string';
        const validatedInput = tokenManager.validateToken(invalidToken);

        expect(validatedInput).toBeNull(); // Valida que o token inválido não é aceito
    });

    test('should validate multiple tokens correctly', () => {
    logTestProgress('should validate multiple tokens correctly');
        const input1 = 'data1';
        const input2 = 'data2';
        const token1 = tokenManager.generateToken(input1);
        const token2 = tokenManager.generateToken(input2);

        expect(tokenManager.validateToken(token1)).toBe(input1);
        expect(tokenManager.validateToken(token2)).toBe(input2);
    });

    test('should detect tokens with tampered checksum', () => {
    logTestProgress('should detect tokens with tampered checksum');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        // Altera o checksum no token
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, saltIndex, checksum] = decoded.split('|');
        const tamperedChecksum = checksum.slice(0, -1) + 'x'; // Modifica o checksum
        const tamperedToken = Buffer.from(`${data}|${saltIndex}|${tamperedChecksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(tamperedToken);
        expect(validatedInput).toBeNull(); // O token deve ser inválido
    });

    test('should detect when salt index is missing', () => {
    logTestProgress('should detect when salt index is missing');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        // Remove o índice do salt
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, , checksum] = decoded.split('|');
        const malformedToken = Buffer.from(`${data}||${checksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(malformedToken);
        expect(validatedInput).toBeNull(); // O token deve ser inválido
    });

    test('should detect when input is tampered with', () => {
    logTestProgress('should detect when input is tampered with');
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        // Altera o dado original
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, saltIndex, checksum] = decoded.split('|');
        const tamperedData = data.slice(0, -1) + 'x'; // Modifica o dado original
        const tamperedToken = Buffer.from(`${tamperedData}|${saltIndex}|${checksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(tamperedToken);
        expect(validatedInput).toBeNull(); // O token deve ser inválido
    });
});
