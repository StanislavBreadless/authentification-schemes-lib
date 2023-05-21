import { I3StepAuthProver, I3StepAuthVerifier, I3StepProtocolDescriptor } from '.';
import { ellipticCurvePair, getModulus, parsePoint, raiseGenerator, randomScalar } from './utils';

import { BN } from 'bn.js';

export interface SchnorrProverMessage1 {
    gToR: string;
}

export interface SchnorrVerifierMessage {
    e: string;
}


export interface SchnorrProverChallenge2 {
    y: string;
}

export interface SchnorrProverData {
    // hex-encoded secret
    secret: string;
    // hex-encoded public key
    publicKey: string
}

export interface SchnorrVerifierData {
    testedPublicKey: string;
}

export class SchnorrProver implements I3StepAuthProver<SchnorrProverMessage1, SchnorrVerifierMessage, SchnorrProverChallenge2> {
    private r: undefined | string;
    
    constructor(private data: SchnorrProverData) {
        this.r = undefined;
    }

    private getR(): string {
        return randomScalar();
    }

    getFirstProverMessage(): SchnorrProverMessage1 { 
        if(this.r) {
            throw new Error("Already generated r");
        }

        this.r = this.getR();
        return {
            gToR: raiseGenerator(this.r).encode('hex', false)
        }
    }

    getProverSecondMessage(verifierRequest: SchnorrVerifierMessage): SchnorrProverChallenge2 {
        if(!this.r) {
            throw new Error("No r");
        }

        const rNum = new BN(this.r, 'hex', 'be');
        const eNum = new BN(verifierRequest.e, 'hex', 'be');
        const secretNum = new BN(this.data.secret, 'hex', 'be');
        const modulus = new BN(getModulus(), 'hex', 'be');
        const y = (rNum.add((secretNum).mul(eNum))).mod(modulus);

        return {
            y: y.toString('hex')
        }
    }
}

export class SchnorrVerifier implements I3StepAuthVerifier<SchnorrProverMessage1, SchnorrVerifierMessage, SchnorrProverChallenge2> {
    private e: undefined | string;
    private gToR: undefined | string;
    private testedPublicKey: undefined | string;

    constructor(data: SchnorrVerifierData) {
        this.testedPublicKey = data.testedPublicKey;
        this.e = undefined;
    }

    getVerifierRequest(proverMessage: SchnorrProverMessage1): SchnorrVerifierMessage {
        if(this.e || this.gToR) {
            throw new Error("Already generated e");
        }

        this.gToR = proverMessage.gToR;
        this.e = randomScalar();
        return {
            e: this.e
        };
    }

    verify(proverResponse: SchnorrProverChallenge2): boolean {
        if(!this.e || !this.gToR || !this.testedPublicKey) {
            throw new Error("No e");
        }

        const gToY = raiseGenerator(proverResponse.y);
        const gToR = parsePoint(this.gToR);
        const publicKey = parsePoint(this.testedPublicKey);
        
        return gToY.eq(gToR.add(publicKey.mul(new BN(this.e, 'hex', 'be'))));
    }
}

export class SchnorrProtocol implements I3StepProtocolDescriptor<
    SchnorrProverMessage1, SchnorrVerifierMessage, SchnorrProverChallenge2, SchnorrVerifierData, SchnorrProverData> {

    newVerifier(verifierParams: SchnorrVerifierData): SchnorrVerifier {
        return new SchnorrVerifier(verifierParams);
    }

    newProver(proverParams: SchnorrProverData): SchnorrProver {
        return new SchnorrProver(proverParams);
    }

    getRandomProverParams(): SchnorrProverData {
        const randomKeyPair = ellipticCurvePair();

        return {
            secret: randomKeyPair.getPrivate('hex'),
            publicKey: randomKeyPair.getPublic(false, 'hex')
        };
    }
}
