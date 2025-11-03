import { describe, test, expect } from '@jest/globals';
import AdvancedTokenManager from '../src/AdvancedTokenManager';
import { performance } from 'perf_hooks';
import { JwtAlgorithm } from '../src/jwt';

describe('AdvancedTokenManager', () => {
    const secretKey = 'my-very-secure-key-12345';
    const salts = ['salt-one', 'salt-two', 'salt-three', 'salt-four', 'salt-five'];

    let tokenManager: AdvancedTokenManager;

    // Mock do console.error e console.warn
    let consoleErrorMock: jest.SpyInstance;
    let consoleWarnMock: jest.SpyInstance;

    beforeAll(() => {
        consoleErrorMock = jest.spyOn(console, 'error').mockImplementation(() => { });
        consoleWarnMock = jest.spyOn(console, 'warn').mockImplementation(() => { }); // Mock para warnings
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
            'Secret must be at least 16 characters long.'
        );
    });

    test('should throw an error if initialized with an empty salt table', () => {
        expect(() => new AdvancedTokenManager(secretKey, [], 'sha256', false)).toThrowError(
            'Salt array cannot be empty or less than 2.'
        );
    });

    test('should extract the original data from a valid token', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const extractedData = tokenManager.extractData(token);

        expect(extractedData).toBe(input);
    });

    test('should return null when extracting data from an invalid token', () => {
        const invalidToken = 'invalid-base64-token';
        const extractedData = tokenManager.extractData(invalidToken);

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
        }).toThrowError(`Invalid salt index: ${invalidSaltIndex}`);
    });


    test('should use provided parameters instead of environment variables', () => {
        const providedSecret = 'provided-secret-key';
        const providedSalts = ['provided-salt1', 'provided-salt2'];

        const tokenManager = new AdvancedTokenManager(providedSecret, providedSalts);
        const config = tokenManager.getConfig();

        expect(config.secret).toBe(providedSecret);
        expect(config.salts).toEqual(providedSalts);
    });

    test('should ignore environment variables when noEnv flag is true', () => {
        const tokenManager = new AdvancedTokenManager(undefined, undefined, 'sha256', true, true);

        const config = tokenManager.getConfig();
        expect(config.secret).not.toBe(process.env.TOKEN_SECRET); // Deve gerar uma nova secret
        expect(config.salts).not.toEqual(process.env.TOKEN_SALTS?.split(',')); // Deve gerar novos salts automaticamente
        expect(config.secret).toBeDefined();
        expect(config.salts.length).toBe(10); // Geração automática cria 10 salts
    });

    test('should throw an error when no secret and no salts are provided and allowAutoGenerate is false', () => {
        delete process.env.TOKEN_SECRET;
        delete process.env.TOKEN_SALTS;
        expect(() => new AdvancedTokenManager(undefined, undefined, 'sha256', false)).toThrowError(
            'Secret must be at least 16 characters long.'
        );
    });

    test('should use environment variables when no parameters are passed', () => {
        process.env.TOKEN_SECRET = 'my-env-secret-key';
        process.env.TOKEN_SALTS = 'env-salt1,env-salt2,env-salt3';
        const tokenManager = new AdvancedTokenManager();
        const config = tokenManager.getConfig();

        expect(config.secret).toBe(process.env.TOKEN_SECRET);
        expect(config.salts).toEqual(process.env.TOKEN_SALTS?.split(','));
    });

    test('should fallback to default behavior if env variables are missing and noEnv is false', () => {
        delete process.env.TOKEN_SECRET;
        delete process.env.TOKEN_SALTS;

        const tokenManager = new AdvancedTokenManager();
        const config = tokenManager.getConfig();

        expect(config.secret).toBeDefined(); // Deve gerar uma nova secret
        expect(config.salts.length).toBe(10); // Deve gerar 10 salts automaticamente
    });

    test('should validate tokens generated using environment variables', () => {
        const tokenManager = new AdvancedTokenManager();
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        const validatedData = tokenManager.validateToken(token);
        expect(validatedData).toBe(input);
    });

    test('should validate tokens generated using noEnv mode', () => {
        const tokenManager = new AdvancedTokenManager(undefined, undefined, 'sha256', true, true);
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);

        const validatedData = tokenManager.validateToken(token);
        expect(validatedData).toBe(input);
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

    test('trims provided secret and salts during initialization', () => {
        const paddedSecret = '   trimmed-secret-value   ';
        const paddedSalts = ['  salt-1  ', 'salt-2   ', '   salt-3'];

        const manager = new AdvancedTokenManager(paddedSecret, paddedSalts, 'sha256', false, true);
        const config = manager.getConfig();

        expect(config.secret).toBe('trimmed-secret-value');
        expect(config.salts).toEqual(['salt-1', 'salt-2', 'salt-3']);
    });

    test('uses injected logger for auto-generated secrets, salts, and validation errors', () => {
        const warnMock = jest.fn();
        const errorMock = jest.fn();
        const manager = new AdvancedTokenManager(undefined, undefined, 'sha256', true, true, {
            logger: { warn: warnMock, error: errorMock }
        });

        expect(warnMock).toHaveBeenCalledTimes(2);
        expect(warnMock).toHaveBeenCalledWith('⚠️ Secret generated automatically. Store it securely.');
        expect(warnMock).toHaveBeenCalledWith('⚠️ Salts generated automatically. Store them securely.');
        expect(errorMock).not.toHaveBeenCalled();

        const invalidToken = 'invalid-base64-token';
        const result = manager.validateToken(invalidToken);
        expect(result).toBeNull();
        expect(errorMock).toHaveBeenCalledTimes(1);
        expect(errorMock).toHaveBeenCalledWith(expect.stringContaining('Error validating token'));
    });

    test('validateToken can throw on demand', () => {
        const manager = new AdvancedTokenManager(secretKey, salts, 'sha256', true, true);
        expect(() => manager.validateToken('invalid-token', { throwOnFailure: true })).toThrow('Invalid salt index: NaN');
    });

    test('validateToken respects throwOnValidationFailure option', () => {
        const manager = new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
            throwOnValidationFailure: true
        });
        expect(() => manager.validateToken('invalid-token')).toThrow('Invalid salt index: NaN');
    });

    test('enforces configured jwtDefaultAlgorithms when verify options omit algorithms', () => {
        const manager = new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
            jwtDefaultAlgorithms: ['HS256']
        });

        const hs256Token = manager.generateJwt({ payload: 'data' }, { algorithm: 'HS256' });
        expect(() => manager.validateJwt(hs256Token)).not.toThrow();

        const hs512Token = manager.generateJwt({ payload: 'data' }, { algorithm: 'HS512' });
        expect(() => manager.validateJwt(hs512Token)).toThrow('JWT: algorithm HS512 is not allowed.');
    });

    test('enforces jwtMaxPayloadSize from options', () => {
        const manager = new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
            jwtMaxPayloadSize: 32
        });

        const token = manager.generateJwt({ payload: 'x'.repeat(64) });
        expect(() => manager.validateJwt(token)).toThrow('JWT: payload exceeds maxPayloadSize.');
    });

    test('enforces jwtAllowedClaims from options', () => {
        const manager = new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
            jwtAllowedClaims: ['role']
        });

        const allowedToken = manager.generateJwt({ role: 'admin', iss: 'issuer' });
        expect(() => manager.validateJwt(allowedToken)).not.toThrow();

        const forbiddenToken = manager.generateJwt({ scope: 'admin' });
        expect(() => manager.validateJwt(forbiddenToken)).toThrow('JWT: claim "scope" is not allowed.');
    });

    test('rejects invalid manager options', () => {
        expect(
            () =>
                new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
                    defaultSecretLength: 10
                })
        ).toThrow('defaultSecretLength must be an integer greater than or equal to 16.');

        expect(
            () =>
                new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
                    defaultSaltCount: 1
                })
        ).toThrow('defaultSaltCount must be an integer greater than or equal to 2.');

        expect(
            () =>
                new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
                    jwtDefaultAlgorithms: []
                })
        ).toThrow('jwtDefaultAlgorithms must be a non-empty array when provided.');

        expect(
            () =>
                new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
                    jwtDefaultAlgorithms: ['RS256' as unknown as JwtAlgorithm]
                })
        ).toThrow('Unsupported JWT algorithm in configuration: RS256');

        expect(
            () =>
                new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
                    jwtMaxPayloadSize: 0
                })
        ).toThrow('jwtMaxPayloadSize must be a positive number.');

        expect(
            () =>
                new AdvancedTokenManager(secretKey, salts, 'sha256', true, true, {
                    jwtAllowedClaims: ['']
                })
        ).toThrow('jwtAllowedClaims must be an array of non-empty strings.');
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

    test('Performance of generateToken', () => {
        const input = 'sensitive-data';
        const iterations = 1000; // Number of tokens to generate
        const num_exec = 10;

        const timeUsages:number[]=[];
        for (let i=0; i < num_exec; i++){
            const start = performance.now();
            for (let i = 0; i < iterations; i++) {
                tokenManager.generateToken(input);
            }   
            const end = performance.now();
            timeUsages.push((end - start) / iterations);
        }
        const averageTime =timeUsages.reduce((sum, times)=>sum+times, 0) / timeUsages.length;
        console.log(`Average time for generateToken: ${averageTime.toFixed(6)} ms this test use [${iterations}] iterations for [${num_exec}] times`);
    });

    test('Performance of validateToken', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const iterations = 1000; // Number of tokens to validate
        const num_exec = 10;

        const timeUsages:number[]=[];
        for (let i=0; i < num_exec; i++){
            const start = performance.now();
            for (let i = 0; i < iterations; i++) {
                tokenManager.validateToken(token);
            }   
            const end = performance.now();
            timeUsages.push((end - start) / iterations);
        }
        const averageTime =timeUsages.reduce((sum, times)=>sum+times, 0) / timeUsages.length;
        console.log(`Average time for generateToken: ${averageTime.toFixed(6)} ms this test use [${iterations}] iterations for [${num_exec}] times`);
    });

    test('Memory usage of generateToken', () => {
        const input = 'sensitive-data';
        const iterations = 1000; // Number of tokens to generate
        const num_exec = 10;

        const memoryUsages:number[] = [];
        for (let i = 0; i < num_exec; i++) {
            if (typeof global.gc === 'function') {
                global.gc();
            }
            // Captura o uso inicial de memória
            const initialMemory = process.memoryUsage().heapUsed;

            for (let i = 0; i < iterations; i++) {
                tokenManager.generateToken(input);
            }

            // Captura o uso final de memória
            const finalMemory = process.memoryUsage().heapUsed;
            memoryUsages.push(Math.max((finalMemory - initialMemory) / 1024 / 1024, 0)); // Converte para MB
        }
        const averageMemoryUsed = memoryUsages.reduce((sum, usage) => sum + usage, 0) / memoryUsages.length;

        console.log(`Average memory used by generateToken: ${averageMemoryUsed.toFixed(4)} MB this test uses [${iterations}] iterations for [${num_exec}] times`);
    });

    test('Memory usage of validateToken', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const iterations = 1000; // Number of tokens to validate
        const num_exec = 10;

        const memoryUsages:number[] = [];
        for (let i = 0; i < num_exec; i++) {
            if (typeof global.gc === 'function') {
                global.gc();
            }
            // Captura o uso inicial de memória
            const initialMemory = process.memoryUsage().heapUsed;

            for (let i = 0; i < iterations; i++) {
                tokenManager.validateToken(token);
            }

            // Captura o uso final de memória
            const finalMemory = process.memoryUsage().heapUsed;
            memoryUsages.push(Math.max((finalMemory - initialMemory) / 1024 / 1024, 0)); // Converte para MB
        }
        const averageMemoryUsed = memoryUsages.reduce((sum, usage) => sum + usage, 0) / memoryUsages.length;

        console.log(`Average memory used by generateToken: ${averageMemoryUsed.toFixed(4)} MB this test uses [${iterations}] iterations for [${num_exec}] times`);
    });


});
