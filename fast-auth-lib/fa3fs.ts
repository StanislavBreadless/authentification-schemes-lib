import sha256 from 'sha256';
import { I2StepAuthProver, I2StepAuthVerifier, I2StepProtocolDescriptor } from '.';
import { ellipticCurvePair, getModulus, parsePoint, raiseGenerator, randomScalar } from './utils';
import { BN } from 'bn.js';

export interface FA3FSVerifierMessage {
    r: string;
}

export interface FA3FSProverMessage {
    y: string;
    t: string;
    e: string;
}

export interface FA3FSProverData {
    // hex-encoded secret
    secret: string;
    // hex-encoded public key
    publicKey: string
}

export interface FA3FSVerifierData {
    testedPublicKey: string;
}

export class FA3FSProver implements I2StepAuthProver<FA3FSVerifierMessage, FA3FSProverMessage> {
    private v: undefined | string;
    private t: undefined | string;
    private e: undefined | string;
    
    constructor(private data: FA3FSProverData) {
    }

    getProverMessage(verifierRequest: FA3FSVerifierMessage): FA3FSProverMessage { 
        if(this.v) {
            throw new Error("Already generated v");
        }
        if(this.t)  {
            throw new Error("Already generated gToV");
        }

        this.v = randomScalar();
        this.t = raiseGenerator(this.v).encode('hex', false);
        this.e = (new BN(sha256(
            raiseGenerator('01').encode('hex', false) + this.data.publicKey + this.t + verifierRequest.r
        ), 'hex', 'be')).mod(getModulus()).toString('hex');

        const y = new BN(this.v, 'hex', 'be').add(new BN(this.e, 'hex', 'be').mul(new BN(this.data.secret, 'hex', 'be'))).toString('hex');

        return {
            y,
            t: this.t,
            e: this.e
        }
    }
}

export class FA3FSVerifier implements I2StepAuthVerifier<FA3FSVerifierMessage, FA3FSProverMessage> {
    private r: undefined | string;
    private testedPublicKey: undefined | string;

    constructor(data: FA3FSVerifierData) {
        this.testedPublicKey = data.testedPublicKey;
    }

    getVerifierRequest(): FA3FSVerifierMessage {
        if(this.r) {
            throw new Error("Already generated r");
        }

        this.r = randomScalar();

        return {
            r: this.r
        }
    }

    verify(proverResponse: FA3FSProverMessage): boolean {
        if(!this.testedPublicKey) {
            throw new Error("No e");
        }

        // 1. Check that e was calculated correctly
        const expectedE = new BN(sha256(
            raiseGenerator('01').encode('hex', false) + this.testedPublicKey + proverResponse.t + this.r
        ), 'hex', 'be').mod(getModulus()).toString('hex');
        if(expectedE !== proverResponse.e) {
            // E was invalid
            return false;
        }

        const gToY = raiseGenerator(proverResponse.y);
        const gToR = parsePoint(proverResponse.t);
        const publicKey = parsePoint(this.testedPublicKey);
        
        return gToY.eq(gToR.add(publicKey.mul(new BN(expectedE, 'hex', 'be'))));
    }
}

export class FA3FSProtocol implements I2StepProtocolDescriptor<
    FA3FSVerifierMessage, FA3FSProverMessage, FA3FSVerifierData, FA3FSProverData> {

    newVerifier(verifierParams: FA3FSVerifierData): FA3FSVerifier {
        return new FA3FSVerifier(verifierParams);
    }

    newProver(proverParams: FA3FSProverData): FA3FSProver {
        return new FA3FSProver(proverParams);
    }

    getRandomProverParams(): FA3FSProverData {
        const randomKeyPair = ellipticCurvePair();

        return {
            secret: randomKeyPair.getPrivate('hex'),
            publicKey: randomKeyPair.getPublic(false, 'hex')
        };
    }
}

