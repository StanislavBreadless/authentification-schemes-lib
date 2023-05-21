"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const schnorr_1 = require("../schnorr");
describe('Test Schnorr protocol', () => {
    it('Should perform a successful key exchange', () => {
        const protocol = new schnorr_1.SchnorrProtocol();
        const proverParams = protocol.getRandomProverParams();
        const prover = protocol.newProver(proverParams);
        const verifier = protocol.newVerifier({ testedPublicKey: proverParams.publicKey });
        const proverMessage1 = prover.getFirstProverMessage();
        const verifierMessage = verifier.getVerifierRequest(proverMessage1);
        const proverMessage2 = prover.getProverSecondMessage(verifierMessage);
        (0, chai_1.expect)(verifier.verify(proverMessage2)).to.be.true;
    });
});
