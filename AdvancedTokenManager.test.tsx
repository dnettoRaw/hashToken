import { describe, test, expect } from '@jest/globals';
import AdvancedTokenManager from './AdvancedTokenManager'; // Ajuste o caminho para a classe

describe('AdvancedTokenManager', () => {
    const secretKey = 'my-very-secure-key-12345';
    const salts = ['salt-one', 'salt-two', 'salt-three', 'salt-four', 'salt-five'];

    let tokenManager: AdvancedTokenManager;

    beforeEach(() => {
        // Inicializa uma nova instância antes de cada teste
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

        // Modifica o token para simular um token inválido
        const invalidToken = token.slice(0, -1) + 'x';
        const validatedInput = tokenManager.validateToken(invalidToken);

        expect(validatedInput).toBeNull();
    });

    test('should return null for a token with an invalid salt index', () => {
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
        const input = 'sensitive-data';
        const token1 = tokenManager.generateToken(input);
        const token2 = tokenManager.generateToken(input);

        expect(token1).not.toBe(token2);
    });

    test('should throw an error if initialized with an invalid secret key', () => {
        expect(() => new AdvancedTokenManager('', salts)).toThrowError('A chave secreta deve ter pelo menos 16 caracteres.');
    });

    test('should throw an error if initialized with an empty salt table', () => {
        expect(() => new AdvancedTokenManager(secretKey, [])).toThrowError('A tabela de salts não pode estar vazia.');
    });
});
