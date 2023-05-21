"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SchnorrProtocol = exports.SchnorrVerifier = exports.SchnorrProver = void 0;
const utils_1 = require("./utils");
const bn_js_1 = require("bn.js");
class SchnorrProver {
    constructor(data) {
        this.data = data;
        this.r = undefined;
    }
    getR() {
        return (0, utils_1.randomScalar)();
    }
    getFirstProverMessage() {
        if (this.r) {
            throw new Error("Already generated r");
        }
        this.r = this.getR();
        return {
            gToR: (0, utils_1.raiseGenerator)(this.r).encode('hex', false)
        };
    }
    getProverSecondMessage(verifierRequest) {
        if (!this.r) {
            throw new Error("No r");
        }
        const rNum = new bn_js_1.BN(this.r, 'hex', 'be');
        const eNum = new bn_js_1.BN(verifierRequest.e, 'hex', 'be');
        const secretNum = new bn_js_1.BN(this.data.secret, 'hex', 'be');
        const modulus = new bn_js_1.BN((0, utils_1.getModulus)(), 'hex', 'be');
        const y = (rNum.add((secretNum).mul(eNum))).mod(modulus);
        return {
            y: y.toString('hex')
        };
    }
}
exports.SchnorrProver = SchnorrProver;
class SchnorrVerifier {
    constructor(data) {
        this.testedPublicKey = data.testedPublicKey;
        this.e = undefined;
    }
    getVerifierRequest(proverMessage) {
        if (this.e || this.gToR) {
            throw new Error("Already generated e");
        }
        this.gToR = proverMessage.gToR;
        this.e = (0, utils_1.randomScalar)();
        return {
            e: this.e
        };
    }
    verify(proverResponse) {
        if (!this.e || !this.gToR || !this.testedPublicKey) {
            throw new Error("No e");
        }
        const gToY = (0, utils_1.raiseGenerator)(proverResponse.y);
        const gToR = (0, utils_1.parsePoint)(this.gToR);
        const publicKey = (0, utils_1.parsePoint)(this.testedPublicKey);
        return gToY.eq(gToR.add(publicKey.mul(new bn_js_1.BN(this.e, 'hex', 'be'))));
    }
}
exports.SchnorrVerifier = SchnorrVerifier;
class SchnorrProtocol {
    newVerifier(verifierParams) {
        return new SchnorrVerifier(verifierParams);
    }
    newProver(proverParams) {
        return new SchnorrProver(proverParams);
    }
    getRandomProverParams() {
        const randomKeyPair = (0, utils_1.ellipticCurvePair)();
        return {
            secret: randomKeyPair.getPrivate('hex'),
            publicKey: randomKeyPair.getPublic(false, 'hex')
        };
    }
}
exports.SchnorrProtocol = SchnorrProtocol;
