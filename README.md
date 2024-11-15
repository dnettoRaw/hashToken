
# AdvancedTokenManager / Gerenciador de Token Avançado

---

## English

**AdvancedTokenManager** is a TypeScript library designed to generate and validate secure tokens with enhanced obfuscation. Ideal for applications requiring data security, such as authentication, information signing, or secure storage.

### Why use AdvancedTokenManager?

1. **Robust Security**:
   - Uses HMAC with a private secret to ensure token integrity.
   - Randomly adds a salt to each token, making data difficult to decipher.

2. **Flexibility**:
   - Supports various hash algorithms, such as `sha256` (default) or `sha512`.
   - Customizable `secrets` and `salts` configuration.

3. **Ease of Integration**:
   - Automatic generation of `secret` and `salts` if required.
   - Supports extracting original data from valid tokens.

### Installation

```bash
npm i hash-token
```

### Code Example

#### Example with Manual Configuration

```typescript
import AdvancedTokenManager from 'hash-token';

// Example using .env or manual configuration
const secretKey = process.env.SECRET_KEY || "secure-key";
const salts = process.env.SALTS?.split(',') || ["salt1", "salt2", "salt3"];

// Initialize token manager
const tokenManager = new AdvancedTokenManager(secretKey, salts);

// Generate token
const inputData = "sensitive-data";
const token = tokenManager.generateToken(inputData);
console.log("Generated Token:", token);

// Validate token
const validatedData = tokenManager.validateToken(token);
if (validatedData) {
    console.log("Valid Token:", validatedData);
} else {
    console.log("Invalid Token");
}
```

#### Example with Automatic Generation (Caution)

```typescript
import AdvancedTokenManager from 'hash-token';

// Automatically generate secret and salts
const tokenManager = new AdvancedTokenManager();

// Print configuration (save these values securely)
const config = tokenManager.getConfig();
console.warn("⚠️ Auto-generated values detected. Save these in a secure location:");
console.log("SECRET:", config.secret);
console.log("SALTS:", config.salts.join(','));

// Generate and validate token
const inputData = "auto-generated-data";
const token = tokenManager.generateToken(inputData);
console.log("Generated Token:", token);

const validatedData = tokenManager.validateToken(token);
if (validatedData) {
    console.log("Valid Token:", validatedData);
} else {
    console.log("Invalid Token");
}
```

**Important:** The auto-generated `secret` and `salts` are temporary and should be securely stored in your `.env` file or another secure location to ensure consistent behavior across sessions.

# Forced Salt Index Usage 

With the latest update, **AdvancedTokenManager** now supports the option to force the use of a specific salt index during token generation. This feature allows you to define which salt will be used for added control and predictability.

### How it works:

- The `generateToken` method now accepts an optional second parameter: `forcedSaltIndex`.
- If provided, the specified index will be used instead of a randomly selected one.
- The `forcedSaltIndex` is validated to ensure it exists within the salt table range.

### Example:

```typescript
import AdvancedTokenManager from 'hash-token';

const secretKey = 'my-secure-key';
const salts = ['salt1', 'salt2', 'salt3'];

const tokenManager = new AdvancedTokenManager(secretKey, salts);

const input = 'sensitive-data';
const forcedIndex = 1; // Force the use of the second salt

const token = tokenManager.generateToken(input, forcedIndex);
console.log('Generated Token:', token);

// Validate the token
const validatedData = tokenManager.validateToken(token);
if (validatedData) {
    console.log('Valid Token:', validatedData);
} else {
    console.log('Invalid Token');
}
```
## **Important Notes**

- Forcing a salt index requires that the index exists in the salt table. If an invalid index is provided, an error will be thrown.

---

## Português

O **AdvancedTokenManager** é uma biblioteca em TypeScript projetada para gerar e validar tokens seguros com ofuscação adicional. Ideal para aplicações que exigem segurança de dados, como autenticação, assinatura de informações ou armazenamento seguro.

### Por que usar o AdvancedTokenManager?

1. **Segurança Robusta**:
   - Utiliza HMAC com um segredo privado para garantir a integridade dos tokens.
   - Adiciona um salt aleatório para cada token, dificultando a decifração.

2. **Flexibilidade**:
   - Suporta diferentes algoritmos de hash, como `sha256` (padrão) ou `sha512`.
   - Configuração personalizável de `secrets` e `salts`.

3. **Fácil Integração**:
   - Geração automática de `secret` e `salts`, se necessário.
   - Suporte para extrair dados originais de tokens válidos.

### Instalação

```bash
npm i hash-token
```

### Código de Exemplo

#### Exemplo com Configuração Manual

```typescript
import AdvancedTokenManager from 'hash-token';

// Exemplo usando .env ou configuração manual
const secretKey = process.env.SECRET_KEY || "chave-secreta";
const salts = process.env.SALTS?.split(',') || ["sal1", "sal2", "sal3"];

// Inicializar o gerenciador de tokens
const tokenManager = new AdvancedTokenManager(secretKey, salts);

// Gerar token
const dados = "dados-sensíveis";
const token = tokenManager.generateToken(dados);
console.log("Token Gerado:", token);

// Validar token
const dadosValidados = tokenManager.validateToken(token);
if (dadosValidados) {
    console.log("Token Válido:", dadosValidados);
} else {
    console.log("Token Inválido");
}
```

#### Exemplo com Geração Automática (Cuidado)

```typescript
import AdvancedTokenManager from 'hash-token';

// Gerar secret e salts automaticamente
const tokenManager = new AdvancedTokenManager();

// Exibir configuração (salve esses valores de forma segura)
const config = tokenManager.getConfig();
console.warn("⚠️ Valores gerados automaticamente detectados. Salve-os em um local seguro:");
console.log("SECRET:", config.secret);
console.log("SALTS:", config.salts.join(','));

// Gerar e validar token
const dados = "dados-gerados-automaticamente";
const token = tokenManager.generateToken(dados);
console.log("Token Gerado:", token);

const dadosValidados = tokenManager.validateToken(token);
if (dadosValidados) {
    console.log("Token Válido:", dadosValidados);
} else {
    console.log("Token Inválido");
}
```

**Importante:** Os valores `secret` e `salts` gerados automaticamente são temporários e devem ser armazenados com segurança em um arquivo `.env` ou outro local seguro para garantir comportamento consistente entre sessões.

# Uso de Índices de Salt Forçados

Com a atualização mais recente, o **AdvancedTokenManager** agora suporta a opção de forçar o uso de um índice de salt específico durante a geração de tokens. Esse recurso permite definir qual salt será utilizado, oferecendo mais controle e previsibilidade.

### Como funciona:

- O método `generateToken` agora aceita um segundo parâmetro opcional: `forcedSaltIndex`.
- Se fornecido, o índice especificado será usado em vez de um selecionado aleatoriamente.
- O `forcedSaltIndex` é validado para garantir que existe dentro do intervalo da tabela de salts.

### Exemplo:

```typescript
import AdvancedTokenManager from 'hash-token';

const secretKey = 'minha-chave-secreta';
const salts = ['sal1', 'sal2', 'sal3'];

const tokenManager = new AdvancedTokenManager(secretKey, salts);

const dados = 'dados-sensiveis';
const indiceForcado = 1; // Força o uso do segundo salt

const token = tokenManager.generateToken(dados, indiceForcado);
console.log('Token Gerado:', token);

// Validar o token
const dadosValidados = tokenManager.validateToken(token);
if (dadosValidados) {
    console.log('Token Válido:', dadosValidados);
} else {
    console.log('Token Inválido');
}
```

---

##  **Notas Importantes**

- Forçar um índice de salt exige que o índice exista na tabela de salts. Se um índice inválido for fornecido, um erro será lançado.

---

## Testing / Testes

**English**:
Run tests using Jest to ensure proper functionality under various scenarios, such as tampered tokens or invalid salts.

**Português**:
Execute testes com Jest para garantir o funcionamento correto em diversos cenários, como tokens adulterados ou salts inválidos.

```bash
npm install --save-dev jest @types/jest ts-jest
npm test
```

---

## License / Licença

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

Este projeto está licenciado sob a [Licença MIT](https://opensource.org/licenses/MIT).

---

## Contact / Contato

For questions or suggestions, reach out at / Para dúvidas ou sugestões, entre em contato em: **[contac@dnetto.dev](mailto:contac@dnetto.dev)**.
