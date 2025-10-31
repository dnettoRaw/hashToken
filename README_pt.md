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

## JWT (nativo, sem dependências)

`hash-token` agora inclui uma implementação de JSON Web Token baseada apenas no `crypto` do Node.js, sem bibliotecas extras. Ela reforça as validações de segurança, bloqueia algoritmos inseguros e funciona lado a lado com a classe `AdvancedTokenManager`.

### Utilitários principais

| Helper | Descrição |
| --- | --- |
| `signJwt(payload, options)` | Gera um JWT assinado com HMAC (HS256 ou HS512). |
| `verifyJwt(token, options)` | Valida estrutura, assinatura e claims antes de retornar o payload. |

### Opções de assinatura

| Opção | Tipo | Padrão | Observações |
| --- | --- | --- | --- |
| `secret` | `string` | — | Obrigatório. Segredo HMAC usado para assinar. |
| `algorithm` | `'HS256' \| 'HS512'` | `HS256` | Define o digest HMAC. |
| `expiresIn` | `number` (segundos) | — | Adiciona o claim `exp` relativo ao tempo atual. |
| `notBefore` | `number` (segundos) | — | Adiciona o claim `nbf` relativo ao tempo atual. |
| `issuedAt` | `number` (segundos) | agora | Substitui o `iat` automático. |
| `issuer` | `string` | — | Garante consistência do claim `iss`. |
| `audience` | `string \| string[]` | — | Aceita um ou vários públicos. |
| `subject` | `string` | — | Define o claim `sub`. |

### Opções de verificação

| Opção | Tipo | Padrão | Observações |
| --- | --- | --- | --- |
| `secret` | `string` | — | Obrigatório. Deve corresponder ao segredo usado na assinatura. |
| `algorithms` | `JwtAlgorithm[]` | todos suportados | Restringe os algoritmos aceitos. |
| `clockTolerance` | `number` (segundos) | `0` | Tolera pequenos desvios de relógio em `exp`, `nbf`, `iat`. |
| `maxAge` | `number` (segundos) | — | Limita a vida útil contando a partir de `iat`. |
| `issuer` | `string \| string[]` | — | Lista de emissores esperados. Falha se ausente ou divergente. |
| `audience` | `string \| string[]` | — | Público esperado. |
| `subject` | `string` | — | Sujeito esperado. |

### Exemplo rápido

```typescript
import { signJwt, verifyJwt } from 'hash-token';

const secret = 'troque-este-valor';

const token = signJwt(
    { usuarioId: 'u-123', perfil: 'admin' },
    { secret, algorithm: 'HS512', expiresIn: 300 }
);

const payload = verifyJwt(token, {
    secret,
    algorithms: ['HS512'],
    audience: 'dashboard'
});

console.log(payload);
```

Consulte também os novos exemplos completos em [`examples/`](./examples):

- [`sign-verify.ts`](./examples/sign-verify.ts)
- [`with-claims.ts`](./examples/with-claims.ts)
- [`manager-integration.ts`](./examples/manager-integration.ts)

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

