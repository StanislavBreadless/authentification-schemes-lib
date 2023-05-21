"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const chai_1 = require("chai");
const fa3fs_1 = require("../fa3fs");
describe('Test FA3FS protocol', () => {
    it('Should perform a successful key exchange', () => {
        const protocol = new fa3fs_1.FA3FSProtocol();
        const proverParams = protocol.getRandomProverParams();
        const prover = protocol.newProver(proverParams);
        const verifier = protocol.newVerifier({ testedPublicKey: proverParams.publicKey });
        const verifierMessage = verifier.getVerifierRequest();
        const proverMessage = prover.getProverMessage(verifierMessage);
        (0, chai_1.expect)(verifier.verify(proverMessage)).to.be.true;
    });
});
