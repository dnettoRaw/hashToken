
# AdvancedTokenManager

O **AdvancedTokenManager** é uma biblioteca em TypeScript projetada para gerar e validar tokens seguros, garantindo integridade e ofuscação. Ele utiliza HMAC (Hash-based Message Authentication Code) com um segredo privado, além de uma tabela predefinida de salts para reforçar a segurança, dificultando ataques de engenharia reversa ou modificação maliciosa de tokens.

---

## Por que usar o AdvancedTokenManager?

1. **Segurança Robusta**:
   - Utiliza HMAC com um segredo privado para garantir a integridade dos tokens.
   - Ofusca os dados com um índice de salt, tornando difícil acessar ou decifrar os dados originais.

2. **Flexibilidade**:
   - Suporta diferentes algoritmos de hash, como `sha256` (padrão) ou `sha512`.
   - Permite configurar uma tabela de salts personalizada.

3. **Resistência a Ataques**:
   - Mesmo que o token seja interceptado, ele não pode ser validado ou recriado sem o segredo privado e a tabela de salts.

---

## Como funciona?

### Geração de Tokens

- A função `generateToken` seleciona um salt aleatório da tabela de salts e calcula um checksum utilizando a string de entrada, o salt e o segredo privado.
- O token gerado é codificado em Base64 e contém:
  - Dados originais.
  - Índice do salt.
  - Checksum.

### Validação de Tokens

- A função `validateToken` decodifica o token para obter os dados originais, o índice do salt e o checksum.
- Recalcula o checksum usando os mesmos parâmetros e compara com o checksum original.
- Retorna os dados originais se o token for válido; caso contrário, retorna `null`.

---

## Exemplo de Uso

### Instalação

Adicione o AdvancedTokenManager ao seu projeto:

```bash
npm install advanced-token-manager
```

### Código de Exemplo

```typescript
import AdvancedTokenManager from 'advanced-token-manager';

const secretKey = "minha-chave-secreta-muito-segura"; // Mantenha esta chave privada!
const salts = ["salt-um", "salt-dois", "salt-tres", "salt-quatro", "salt-cinco"]; // Tabela de salts

const tokenManager = new AdvancedTokenManager(secretKey, salts);

const input = "dados-sensitivos";
const token = tokenManager.generateToken(input);
console.log("Token Gerado:", token);

const validatedInput = tokenManager.validateToken(token);
if (validatedInput) {
    console.log("Token Válido! Dados Originais:", validatedInput);
} else {
    console.log("Token Inválido!");
}
```

---

### Saída Esperada

```bash
Token Gerado: eyJkYWRvcy1zZW5zaXRpdm9zIjog...
Token Válido! Dados Originais: dados-sensitivos
```

---

## Testes

### Por que testar?

Os testes garantem que o **AdvancedTokenManager** funcione corretamente em diversos cenários, incluindo casos extremos, como tokens modificados ou índices de salt inválidos.

### Configuração dos Testes

1. Instale as dependências de teste:

```bash
npm install --save-dev jest @types/jest ts-jest
```

2. Configure o Jest no `package.json`:

```json
"scripts": {
  "test": "jest"
}
```

3. Crie o arquivo de teste `AdvancedTokenManager.test.ts`:

```typescript
import { describe, test, expect } from '@jest/globals';
import AdvancedTokenManager from './AdvancedTokenManager';

describe('AdvancedTokenManager', () => {
    const secretKey = 'my-very-secure-key-12345';
    const salts = ['salt-one', 'salt-two', 'salt-three', 'salt-four', 'salt-five'];

    let tokenManager: AdvancedTokenManager;

    beforeEach(() => {
        tokenManager = new AdvancedTokenManager(secretKey, salts);
    });

    test('should generate a valid token', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        expect(token).toBeDefined();
    });

    test('should validate a valid token correctly', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        expect(tokenManager.validateToken(token)).toBe(input);
    });

    test('should return null for a modified token', () => {
        const input = 'sensitive-data';
        const token = tokenManager.generateToken(input);
        const invalidToken = token.slice(0, -1) + 'x';
        expect(tokenManager.validateToken(invalidToken)).toBeNull();
    });

    test('should generate unique tokens for the same input with different salts', () => {
        const input = 'sensitive-data';
        const token1 = tokenManager.generateToken(input);
        const token2 = tokenManager.generateToken(input);
        expect(token1).not.toBe(token2);
    });
});
```

4. Execute os testes:

```bash
npm test
```

---

## Estrutura do Projeto

```
src/
├── AdvancedTokenManager.ts   # Implementação da classe
├── AdvancedTokenManager.test.ts # Testes automatizados
README.md                     # Documentação
package.json                  # Configurações do projeto
```

---

## Contribuindo

1. Faça um fork do repositório.
2. Crie uma nova branch (`git checkout -b feature/minha-nova-feature`).
3. Faça commit das alterações (`git commit -m 'Adiciona nova feature'`).
4. Envie suas alterações para o GitHub (`git push origin feature/minha-nova-feature`).
5. Abra um Pull Request.

---

## Licença

Este projeto está licenciado sob a [MIT License](https://opensource.org/licenses/MIT). Sinta-se à vontade para usá-lo e modificá-lo como desejar.

---
## Contato

Para dúvidas ou sugestões, entre em contato em: **[contac@dnetto.dev](contac@dnetto.dev)**.
