import { expect } from 'chai';
import { FA3FSProtocol } from '../fa3fs';

describe('Test FA3FS protocol', () => {
    it('Should perform a successful key exchange', () => {
        const protocol = new FA3FSProtocol();

        const proverParams = protocol.getRandomProverParams();
        const prover = protocol.newProver(proverParams);
        const verifier = protocol.newVerifier({ testedPublicKey: proverParams.publicKey });

        const verifierMessage = verifier.getVerifierRequest();
        const proverMessage = prover.getProverMessage(verifierMessage);

        expect(verifier.verify(proverMessage)).to.be.true;
    });
});

