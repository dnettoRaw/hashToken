# Gerenciador de Token Avançado

---

## Links

- [Versão em Inglês](./README.md)
- [Versão em Francês](./README_fr.md)

## Visão Geral

**AdvancedTokenManager** é uma biblioteca TypeScript para gerar e validar tokens seguros com ofuscação avançada. Ideal para aplicações que exigem segurança de dados, como autenticação, assinatura de informações ou armazenamento seguro.

---

## Funcionalidades

### Desempenho

Os testes de desempenho mostram que a geração e validação dos tokens são extremamente rápidas (resultado médio de 1.000 iterações realizadas 10 vezes). Esses testes foram conduzidos em um processador Apple M1.
- Uso médio de memória durante a geração de tokens: **0,9766 MB**.
- Uso médio de memória durante a validação de tokens: **0,9842 MB**.
- Tempo médio para `generateToken`: **0,002953 ms**.
- Tempo médio para `validateToken`: **0,002344 ms**.

### Segurança

- Utiliza HMAC com um segredo privado para garantir a integridade dos tokens.
- Adiciona um salt aleatório a cada token, tornando a decriptação difícil.

### Flexibilidade

- Suporta diversos algoritmos de hash (`sha256` por padrão, `sha512`).
- Configuração personalizável de `secret` e `salts`.

### Fácil Integração

- Geração automática de `secret` e `salts`, se necessário.
- Suporte para extrair os dados originais dos tokens válidos.

---

## Instalação

```bash
npm i hash-token
```

---

## Exemplos

### Configuração Manual

```typescript
import AdvancedTokenManager from 'hash-token';

const secretKey = process.env.SECRET_KEY || "chave-segura";
const salts = process.env.SALTS?.split(',') || ["sal1", "sal2", "sal3"];

const tokenManager = new AdvancedTokenManager(secretKey, salts);

const token = tokenManager.generateToken("dados-sensiveis");
console.log("Token Gerado:", token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? "Token Válido:" : "Token Inválido");
```

### Geração Automática (Use com Cuidado)

```typescript
import AdvancedTokenManager from 'hash-token';

const tokenManager = new AdvancedTokenManager();

const config = tokenManager.getConfig();
console.warn("⚠️ Salve esses valores de forma segura:");
console.log("SECRET:", config.secret);
console.log("SALTS:", config.salts.join(','));

const token = tokenManager.generateToken("dados-gerados-automaticamente");
console.log("Token Gerado:", token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? "Token Válido:" : "Token Inválido");
```

**Importante:** Salve o `secret` e os `salts` gerados automaticamente para garantir um comportamento consistente.

### Uso de Índice de Salt Forçado

Você pode forçar o uso de um índice específico de salt ao gerar tokens para maior controle e previsibilidade.

```typescript
import AdvancedTokenManager from 'hash-token';

const tokenManager = new AdvancedTokenManager('chave-segura', ['sal1', 'sal2', 'sal3']);

const token = tokenManager.generateToken('dados-sensiveis', 1);
console.log('Token Gerado:', token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? 'Token Válido:' : 'Token Inválido');
```

**Nota:** Certifique-se de que o índice de salt forçado exista, caso contrário, um erro será lançado.

---

## Testes

Use o Jest para testar a funcionalidade em vários cenários, como tokens adulterados ou salts inválidos.

```bash
npm install --save-dev jest @types/jest ts-jest
npm test
```

---

## Licença

Este projeto está licenciado sob a [Licença MIT](https://opensource.org/licenses/MIT).

---

## Contato

Para dúvidas ou sugestões, por favor, abra uma issue no [GitHub](https://github.com/dnettoRaw/hashToken/issues).

