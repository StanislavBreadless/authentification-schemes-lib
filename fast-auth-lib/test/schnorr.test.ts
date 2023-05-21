import { expect } from 'chai';

import { SchnorrProtocol } from '../schnorr';

describe('Test Schnorr protocol', () => {
    it('Should perform a successful key exchange', () => {
        const protocol = new SchnorrProtocol();

        const proverParams = protocol.getRandomProverParams();
        const prover = protocol.newProver(proverParams);
        const verifier = protocol.newVerifier({ testedPublicKey: proverParams.publicKey });

        const proverMessage1 = prover.getFirstProverMessage();
        const verifierMessage = verifier.getVerifierRequest(proverMessage1);
        const proverMessage2 = prover.getProverSecondMessage(verifierMessage);

        expect(verifier.verify(proverMessage2)).to.be.true;
    });
});

