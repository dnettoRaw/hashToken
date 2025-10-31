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

### JWT (nativo, sem dependências)

- Assinatura HS256/HS512 nativa usando apenas `crypto` do Node.js.
- Codificação Base64URL sem padding e validações rígidas de header/payload.
- Claims opcionais como `expiresIn`, `notBefore`, `issuer`, `audience` e `subject` prontas para uso.
- Funciona de forma independente ou via `AdvancedTokenManager.generateJwt()` / `validateJwt()`.

#### Opções de assinatura

| Opção | Tipo | Descrição |
| --- | --- | --- |
| `algorithm` | `'HS256' \| 'HS512'` | Seleciona o algoritmo HMAC (padrão HS256). |
| `expiresIn` | `number` (segundos) | Define `exp` relativo ao `iat`. Precisa ser positivo. |
| `notBefore` | `number` (segundos) | Define `nbf` relativo ao `iat` para adiar a validade. |
| `issuedAt` | `number` (segundos) | Ajusta o `iat`. Padrão `Date.now()/1000`. |
| `issuer` | `string` | Define `iss`, útil para identificar o emissor. |
| `subject` | `string` | Define `sub`, ideal para IDs de usuário. |
| `audience` | `string \| string[]` | Define `aud` para um ou vários públicos. |

#### Opções de verificação

| Opção | Tipo | Descrição |
| --- | --- | --- |
| `algorithms` | `('HS256' \| 'HS512')[]` | Restringe algoritmos aceitos (padrão permite ambos). |
| `clockTolerance` | `number` (segundos) | Aceita pequeno desvio de relógio para `exp`/`nbf`. |
| `maxAge` | `number` (segundos) | Garante que o `iat` seja recente. Requer `iat`. |
| `issuer` | `string \| string[]` | Valores esperados para `iss`. |
| `audience` | `string \| string[]` | Valores esperados para `aud`. |
| `subject` | `string \| string[]` | Valor esperado para `sub`. |
| `currentTimestamp` | `number` (segundos) | Sobrescreve `Date.now()/1000` para validação determinística. |

#### Exemplo rápido

```typescript
import { signJwt, verifyJwt } from 'hash-token';

const secret = process.env.JWT_SECRET ?? 'super-secreto';

const token = signJwt(
  { userId: 'u-123', scope: ['perfil:ler'] },
  secret,
  { expiresIn: 900, issuer: 'auth-service', audience: ['web'] }
);

const { payload } = verifyJwt(token, secret, { audience: 'web', issuer: 'auth-service' });
console.log(payload.userId); // "u-123"
```

`AdvancedTokenManager` expõe a mesma funcionalidade:

```typescript
const manager = new AdvancedTokenManager('segredo', ['sal-a', 'sal-b']);
const jwt = manager.generateJwt({ workspaceId: '42' }, { expiresIn: 300 });
const result = manager.validateJwt(jwt, { audience: 'dashboard' });
console.log(result.payload.workspaceId);
```

Mais exemplos executáveis estão em [`examples/`](./examples).

#### Dicas de segurança

- Mantenha o segredo JWT privado e realize rotações periódicas.
- Prefira `clockTolerance` ≤ 30 segundos para lidar com diferenças de relógio sem mascarar falhas.
- Valide `issuer`, `audience` e `subject` sempre que possível para evitar reuso indevido entre serviços.

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

