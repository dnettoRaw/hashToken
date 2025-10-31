# hashToken/chatTuning — Agents

## 🧩 1. Refactor Agent
**Papel:** Engenheiro TypeScript  
**Objetivo:** Adicionar `src/jwt.ts` com suporte JWT (HS256/HS512) sem bibliotecas externas e integrar à classe principal.  
**Tarefas:**
- Implementar assinatura/verificação JWT.
- Criar Base64URL encoder/decoder.
- Integrar `generateJwt` e `validateJwt` na API pública.
- Garantir compatibilidade e tipagem strict.

---

## 🛡️ 2. Security Agent
**Papel:** Auditor de segurança  
**Objetivo:** Inspecionar o novo módulo e identificar vulnerabilidades.  
**Checklist:**
- Proibir `alg: none`.
- Comparação com `crypto.timingSafeEqual`.
- Validação rigorosa de claims (`exp`, `nbf`, `iat`).
- Tolerância de tempo segura (`clockTolerance`).
- Sem dependências externas.
- Criar arquivo `SECURITY_NOTES.md` listando ameaças e defesas.

---

## 🧪 3. Test Agent
**Papel:** Engenheiro de testes Jest  
**Objetivo:** Garantir cobertura ≥95% no novo módulo.  
**Tarefas:**
- Criar `__tests__/jwt.spec.ts`.
- Testar sucesso e falha (expiração, algs, truncamento, claims inválidas).
- Validar HS256 e HS512.
- Testes de integração com `AdvancedTokenManager`.

---

## 💡 4. Examples Agent
**Papel:** Criador de exemplos  
**Objetivo:** Criar `examples/` com uso real.  
**Tarefas:**
- `examples/sign-verify.ts` — uso básico.
- `examples/with-claims.ts` — claims completas.
- `examples/manager-integration.ts` — integração no gerenciador.
- Comentários e clareza de execução.

---

## 📚 5. Docs Agent
**Papel:** Editor técnico multilíngue  
**Objetivo:** Atualizar documentação existente.  
**Tarefas:**
- Inserir seção “JWT (nativo, sem dependências)” nos READMEs (EN/PT/FR).
- Adicionar tabela de opções, exemplos e notas de segurança.
- Manter estilo textual atual (mesma voz, estrutura e exemplos).

---

## 🔁 Workflow sugerido
1. Refactor Agent cria `jwt.ts` + integração.  
2. Security Agent audita e gera `SECURITY_NOTES.md`.  
3. Test Agent cria e roda Jest.  
4. Examples Agent adiciona scripts de uso.  
5. Docs Agent atualiza documentação.  
6. Tudo revisado, commit em `chatTuning` e merge após testes passarem.
