import AdvancedTokenManager from './AdvancedTokenManager';

export default AdvancedTokenManager;


// // Exemplo de uso
// const secretKey = "minha-chave-secreta-muito-segura"; // Mantenha esta chave segura!
// const salts = [
//     "salt-um",
//     "salt-dois",
//     "salt-tres",
//     "salt-quatro",
//     "salt-cinco",
// ]; // Tabela de salts predefinidos

// const tokenManager = new AdvancedTokenManager(secretKey, salts);

// const originalString = "dados-muito-sensitivos";
// const token = tokenManager.generateToken(originalString);
// console.log("Token gerado:", token);

// const validatedString = tokenManager.validateToken(token);
// console.log("String validada:", validatedString);

// const invalidToken = token.slice(0, -1) + 'x'; // Modificação proposital para simular um token inválido
// const invalidValidation = tokenManager.validateToken(invalidToken);
// console.log("Validação do token inválido:", invalidValidation);
