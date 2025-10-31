# Gestionnaire de  Avancé

---

## Liens

- [Version en Anglais](./README.md)
- [Version en Portugais](./README_pt.md)

## Aperçu

**AdvancedTokenManager** est une bibliothèque TypeScript pour générer et valider des tokens sécurisés avec une obfuscation avancée. Idéale pour les applications nécessitant la sécurité des données, telles que l'authentification, la signature d'informations ou le stockage sécurisé.

---

## Fonctionnalités

### Performance

Tests de performance montrent que la génération et la validation des tokens sont extrêmement rapides (résultat moyen de 1 000 itérations effectuées 10 fois), Ces tests ont été effectués sur un processeur Apple M1.
- Utilisation moyenne de la mémoire pendant la génération de tokens : **0,9766 MB**.
- Utilisation moyenne de la mémoire pendant la validation de tokens : **0,9842 MB**.
- Le temps moyen pour `generateToken` est de **0,002953 ms**.
- Le temps moyen pour `validateToken` est de **0,002344 ms**.

### Sécurité

- Utilise HMAC avec un secret privé pour garantir l'intégrité des tokens.
- Ajoute un sel aléatoire à chaque jeton, rendant la décryption difficile.

### Flexibilité

- Prend en charge divers algorithmes de hachage (`sha256` par défaut, `sha512`).
- Configuration personnalisable du `secret` et des `sels`.

### Facile à Intégrer

- Génération automatique de `secret` et `sels` si nécessaire.
- Prend en charge l'extraction des données d'origine à partir des tokens valides.

### JWT (natif, sans dépendances)

- Signature HS256/HS512 native basée uniquement sur `crypto` de Node.js.
- Encodage Base64URL sans padding et validations strictes du header et du payload.
- Claims optionnelles telles que `expiresIn`, `notBefore`, `issuer`, `audience` et `subject` prêtes à l'emploi.
- Fonctionne seul ou via `AdvancedTokenManager.generateJwt()` / `validateJwt()`.

#### Options de signature

| Option | Type | Description |
| --- | --- | --- |
| `algorithm` | `'HS256' \| 'HS512'` | Choisit l'algorithme HMAC (HS256 par défaut). |
| `expiresIn` | `number` (secondes) | Définit `exp` par rapport à `iat`. Doit être positif. |
| `notBefore` | `number` (secondes) | Définit `nbf` par rapport à `iat` pour différer la validité. |
| `issuedAt` | `number` (secondes) | Force la valeur de `iat`. Par défaut `Date.now()/1000`. |
| `issuer` | `string` | Renseigne `iss` pour identifier l'émetteur. |
| `subject` | `string` | Renseigne `sub`, idéal pour les identifiants utilisateur. |
| `audience` | `string \| string[]` | Renseigne `aud` pour un ou plusieurs publics. |

#### Options de vérification

| Option | Type | Description |
| --- | --- | --- |
| `algorithms` | `('HS256' \| 'HS512')[]` | Restreint les algorithmes acceptés (par défaut les deux). |
| `clockTolerance` | `number` (secondes) | Tolérance de dérive d'horloge pour `exp`/`nbf`. |
| `maxAge` | `number` (secondes) | Vérifie que `iat` reste récent. Requiert `iat`. |
| `issuer` | `string \| string[]` | Valeurs attendues pour `iss`. |
| `audience` | `string \| string[]` | Valeurs attendues pour `aud`. |
| `subject` | `string \| string[]` | Valeur attendue pour `sub`. |
| `currentTimestamp` | `number` (secondes) | Remplace `Date.now()/1000` pour les tests déterministes. |

#### Exemple rapide

```typescript
import { signJwt, verifyJwt } from 'hash-token';

const secret = process.env.JWT_SECRET ?? 'super-secret';

const token = signJwt(
  { userId: 'u-123', scope: ['profil:lecture'] },
  secret,
  { expiresIn: 900, issuer: 'auth-service', audience: ['web'] }
);

const { payload } = verifyJwt(token, secret, { audience: 'web', issuer: 'auth-service' });
console.log(payload.userId); // "u-123"
```

`AdvancedTokenManager` offre la même API :

```typescript
const manager = new AdvancedTokenManager('secret', ['sel-a', 'sel-b']);
const jwt = manager.generateJwt({ workspaceId: '42' }, { expiresIn: 300 });
const result = manager.validateJwt(jwt, { audience: 'dashboard' });
console.log(result.payload.workspaceId);
```

Des extraits exécutables supplémentaires sont disponibles dans [`examples/`](./examples).

#### Conseils de sécurité

- Gardez le secret JWT privé et effectuez des rotations régulières.
- Utilisez une `clockTolerance` ≤ 30 secondes pour absorber les écarts d'horloge sans masquer les anomalies.
- Validez autant que possible `issuer`, `audience` et `subject` afin d'éviter les réutilisations entre services.

---

## Installation

```bash
npm i hash-token
```

---

## Exemples

### Configuration Manuelle

```typescript
import AdvancedTokenManager from 'hash-token';

const secretKey = process.env.SECRET_KEY || "clé-sécurisée";
const salts = process.env.SALTS?.split(',') || ["sel1", "sel2", "sel3"];

const tokenManager = new AdvancedTokenManager(secretKey, salts);

const token = tokenManager.generateToken("données-sensibles");
console.log("Token Généré :", token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? "Token Valide :" : "Token Invalide");
```

### Génération Automatique (À Utiliser avec Prudence)

```typescript
import AdvancedTokenManager from 'hash-token';

const tokenManager = new AdvancedTokenManager();

const config = tokenManager.getConfig();
console.warn("⚠️ Enregistrez ces valeurs en toute sécurité :");
console.log("SECRET :", config.secret);
console.log("SELS :", config.salts.join(','));

const token = tokenManager.generateToken("données-générées-automatiquement");
console.log("Token Généré :", token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? "Token Valide :" : "Token Invalide");
```

**Important :** Enregistrez le `secret` et les `sels` générés automatiquement pour garantir un comportement cohérent.

### Utilisation d'un Index de Sel Forcé

Vous pouvez forcer l'utilisation d'un index de sel spécifique lors de la génération des tokens pour plus de contrôle et de prévisibilité.

```typescript
import AdvancedTokenManager from 'hash-token';

const tokenManager = new AdvancedTokenManager('ma-clé-sécurisée', ['sel1', 'sel2', 'sel3']);

const token = tokenManager.generateToken('données-sensibles', 1);
console.log('Token Généré :', token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? 'Token Valide :' : 'Token Invalide');
```

**Note :** Assurez-vous que l'index de sel forcé existe, sinon une erreur sera levée.

---

## Tests

Utilisez Jest pour tester la fonctionnalité dans divers scénarios, tels que des tokens altérés ou des sels invalides.

```bash
npm install --save-dev jest @types/jest ts-jest
npm test
```

---

## Licence

Ce projet est sous licence [MIT License](https://opensource.org/licenses/MIT).

---

## Contact

Pour des questions ou des suggestions, veuillez ouvrir une issue sur [GitHub](https://github.com/dnettoRaw/hashToken/issues).

