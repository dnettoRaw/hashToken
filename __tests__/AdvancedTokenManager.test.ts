import { describe, test, expect } from '@jest/globals';
import AdvancedTokenManager from '../src/AdvancedTokenManager';

describe('AdvancedTokenManager', () => {
    const secretKey = 'my-very-secure-key-12345';
    const salts = ['salt-one', 'salt-two', 'salt-three', 'salt-four', 'salt-five'];

    let tokenManager: AdvancedTokenManager;
    
    // Mock do console.error e console.warn
    let consoleErrorMock: jest.SpyInstance;
    let consoleWarnMock: jest.SpyInstance;

    beforeAll(() => {
        consoleErrorMock = jest.spyOn(console, 'error').mockImplementation(() => {});
        consoleWarnMock = jest.spyOn(console, 'warn').mockImplementation(() => {}); // Mock para warnings
    });

    afterAll(() => {
        consoleErrorMock.mockRestore();
        consoleWarnMock.mockRestore(); // Restaura console.warn após os testes
    });

    beforeEach(() => {
        tokenManager = new AdvancedTokenManager(secretKey, salts);
    });

    test('should generate a valid token', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        expect(token).toBeDefined();
        expect(typeof token).toBe('string');
    });

    test('should validate a valid token correctly', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const validatedInput = tokenManager.validateToken(token);

        expect(validatedInput).toBe(input);
    });

    test('should return null for a modified token', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        const invalidToken = token.slice(0, -1) + 'x';
        const validatedInput = tokenManager.validateToken(invalidToken);

        expect(validatedInput).toBeNull();
    });

    test('should return null for a token with an invalid salt index', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, saltIndex, checksum] = decoded.split('|');
        const invalidSaltIndex = salts.length;
        const modifiedToken = Buffer.from(`${data}|${invalidSaltIndex}|${checksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(modifiedToken);
        expect(validatedInput).toBeNull();
    });

    test('should generate unique tokens for the same input with different salts', () => {
        const input = 'sensitive-data';
        const token1 = tokenManager.generateToken(input);
        const token2 = tokenManager.generateToken(input);

        expect(token1).not.toBe(token2);
    });

    test('should throw an error if initialized with an invalid secret key', () => {
        expect(() => new AdvancedTokenManager('', salts, 'sha256', false)).toThrowError(
            'A chave secreta deve ter pelo menos 16 caracteres.'
        );
    });
    
    test('should throw an error if initialized with an empty salt table', () => {
        expect(() => new AdvancedTokenManager(secretKey, [], 'sha256', false)).toThrowError(
            'A tabela de salts não pode estar vazia.'
        );
    });

    test('should extract the original data from a valid token', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const extractedData = tokenManager.extractOriginalData(token);

        expect(extractedData).toBe(input);
    });

    test('should return null when extracting data from an invalid token', () => {
        const invalidToken = 'invalid-base64-token';
        const extractedData = tokenManager.extractOriginalData(invalidToken);

        expect(extractedData).toBeNull();
    });

    test('should generate a token using the specified salt index', () => {
        const input = 'sensitive-data';
        const forcedSaltIndex = 2; // Forçar o uso do índice 2
        const token = tokenManager.generateToken(input, forcedSaltIndex);
    
        // Decodificar o token gerado para verificar o índice do salt usado
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [, saltIndexStr] = decoded.split('|');
        const saltIndex = parseInt(saltIndexStr, 10);
    
        expect(saltIndex).toBe(forcedSaltIndex); // O índice do salt deve ser o especificado
        expect(tokenManager.validateToken(token)).toBe(input); // O token deve ser válido
    });
    
    test('should throw an error when using an invalid forced salt index', () => {
        const input = 'sensitive-data';
        const invalidSaltIndex = 10; // Índice inválido (fora do intervalo de salts)
    
        expect(() => {
            tokenManager.generateToken(input, invalidSaltIndex);
        }).toThrowError(`Índice de salt inválido: ${invalidSaltIndex}`);
    });
    

    test('should generate tokens with automatically generated secrets and salts', () => {
        const autoTokenManager = new AdvancedTokenManager();

        const input = 'auto-sensitive-data';
        const token = autoTokenManager.generateToken(input);

        const validatedData = autoTokenManager.validateToken(token);
        expect(validatedData).toBe(input);

        const config = autoTokenManager.getConfig();
        expect(config.secret).toBeDefined();
        expect(config.secret.length).toBe(32);
        expect(config.salts).toHaveLength(10);
    });

    test('should handle an empty input gracefully', () => {
        const input = '';
        const token = tokenManager.generateToken(input);
        const validatedInput = tokenManager.validateToken(token);

        expect(validatedInput).toBe(input);
    });

    test('should return null for an invalid Base64 token', () => {
        const invalidToken = 'invalid-base64-string';
        const validatedInput = tokenManager.validateToken(invalidToken);

        expect(validatedInput).toBeNull();
    });

    test('should validate multiple tokens correctly', () => {
        const input1 = 'data1';
        const input2 = 'data2';
        const token1 = tokenManager.generateToken(input1);
        const token2 = tokenManager.generateToken(input2);

        expect(tokenManager.validateToken(token1)).toBe(input1);
        expect(tokenManager.validateToken(token2)).toBe(input2);
    });

    test('should detect tokens with tampered checksum', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, saltIndex, checksum] = decoded.split('|');
        const tamperedChecksum = checksum.slice(0, -1) + 'x';
        const tamperedToken = Buffer.from(`${data}|${saltIndex}|${tamperedChecksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(tamperedToken);
        expect(validatedInput).toBeNull();
    });

    test('should detect when salt index is missing', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, , checksum] = decoded.split('|');
        const malformedToken = Buffer.from(`${data}||${checksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(malformedToken);
        expect(validatedInput).toBeNull();
    });

    test('should detect when input is tampered with', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [data, saltIndex, checksum] = decoded.split('|');
        const tamperedData = data.slice(0, -1) + 'x';
        const tamperedToken = Buffer.from(`${tamperedData}|${saltIndex}|${checksum}`).toString('base64');

        const validatedInput = tokenManager.validateToken(tamperedToken);
        expect(validatedInput).toBeNull();
    });

});
