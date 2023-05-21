const authLibrary = require('fast-auth-lib');

const protocol = new authLibrary.FA3FSProtocol();

const proverParams = protocol.getRandomProverParams();
console.log('Параметри прувера: ', proverParams);

// Крок 0. Ініціалізація протоколу та його учасників
const prover = protocol.newProver(proverParams);
const verifier = protocol.newVerifier({ testedPublicKey: proverParams.publicKey });

// Крок 1. Веріфікатор відправляє випадкове значення r
const verifierMessage = verifier.getVerifierRequest();
console.log('Крок 1. Повідомлення веріфікатора: ', verifierMessage);

// Крок 2. Прувер відправляє відповідь на виклик веріфікатора
const proverMessage2 = prover.getProverMessage(verifierMessage);
console.log('Крок 2. Повідомлення прувера: ', proverMessage2);

console.log('Вердикт перевіряючого: ', verifier.verify(proverMessage2));


