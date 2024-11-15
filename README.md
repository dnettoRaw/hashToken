
# AdvancedTokenManager

O **AdvancedTokenManager** é uma classe em TypeScript projetada para gerar e validar tokens seguros, garantindo integridade e ofuscação. Ele utiliza HMAC (Hash-based Message Authentication Code) com um segredo privado, além de uma tabela predefinida de salts para ofuscar ainda mais os dados, dificultando ataques de engenharia reversa ou modificação maliciosa de tokens.

## Por que usar o AdvancedTokenManager?

1. **Segurança Robusta**:
   - Usa HMAC com um segredo privado para garantir a integridade dos tokens.
   - O índice do salt ofusca os dados reais, tornando difícil descobrir os valores originais sem acesso ao sistema.

2. **Flexibilidade**:
   - Suporta diferentes algoritmos de hash, como `sha256` (padrão) ou `sha512`.
   - A tabela de salts pode ser personalizada, e novos salts podem ser adicionados facilmente.

3. **Resistência a Ataques**:
   - Mesmo que o token seja interceptado, não é possível validá-lo ou recriá-lo sem o segredo privado e a tabela de salts.

---

## Como funciona?

### Geração de Tokens

1. A função `generateToken`:
   - Seleciona um salt aleatório da tabela predefinida.
   - Calcula um checksum combinando a string de entrada, o salt selecionado e o segredo privado.
   - Retorna o token codificado em Base64, contendo:
     - Dados originais.
     - Índice do salt.
     - Checksum.

### Validação de Tokens

2. A função `validateToken`:
   - Decodifica o token para obter os dados, índice do salt e checksum.
   - Recupera o salt correspondente ao índice.
   - Recalcula o checksum e o compara com o checksum do token.
   - Retorna os dados originais se o token for válido; caso contrário, retorna `null`.

---

## Exemplo de Uso

### Instalação

Instale as dependências necessárias:

```bash
npm install crypto
```

### Código de Exemplo

```typescript
const secretKey = "minha-chave-secreta-muito-segura"; // Mantenha esta chave privada!
const salts = ["salt-um", "salt-dois", "salt-tres", "salt-quatro", "salt-cinco"]; // Tabela de salts predefinidos

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

### Saída Esperada

```bash
Token Gerado: eyJkYWRvcy1zZW5zaXRpdm9zIjog...
Token Válido! Dados Originais: dados-sensitivos
```

---

## Testes

### Por que testar?

Os testes garantem que o **AdvancedTokenManager** funciona como esperado em diversos cenários, incluindo casos extremos como tokens modificados ou índices de salt inválidos.

### Configurando os Testes

1. Instale o Jest e suas dependências:

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
import AdvancedTokenManager from './AdvancedTokenManager'; // Ajuste o caminho para a classe

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

### Explicação dos Testes

1. **Geração de Tokens Válidos**:
   - Testa se a função `generateToken` retorna um token válido.

2. **Validação de Tokens Válidos**:
   - Testa se um token gerado pode ser validado corretamente e retorna os dados originais.

3. **Detecção de Tokens Modificados**:
   - Testa se um token modificado é detectado como inválido.

4. **Geração de Tokens Únicos**:
   - Verifica se tokens gerados para o mesmo dado de entrada são únicos devido ao uso de salts aleatórios.

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
2. Crie uma nova branch para sua feature (`git checkout -b feature/nova-feature`).
3. Faça commit das alterações (`git commit -m 'Adiciona nova feature'`).
4. Envie suas alterações para o GitHub (`git push origin feature/nova-feature`).
5. Crie um Pull Request.

---

## Licença

Este projeto está licenciado sob a [MIT License](https://opensource.org/licenses/MIT). Sinta-se à vontade para usá-lo e modificá-lo como quiser.

---

## Contato

Para dúvidas ou sugestões, entre em contato em: **[contac@dnetto.dev](contac@dnetto.dev)**.
