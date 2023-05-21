"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.FA3FSProtocol = exports.FA3FSVerifier = exports.FA3FSProver = void 0;
const sha256_1 = __importDefault(require("sha256"));
const utils_1 = require("./utils");
const bn_js_1 = require("bn.js");
class FA3FSProver {
    constructor(data) {
        this.data = data;
    }
    getProverMessage(verifierRequest) {
        if (this.v) {
            throw new Error("Already generated v");
        }
        if (this.t) {
            throw new Error("Already generated gToV");
        }
        this.v = (0, utils_1.randomScalar)();
        this.t = (0, utils_1.raiseGenerator)(this.v).encode('hex', false);
        this.e = (new bn_js_1.BN((0, sha256_1.default)((0, utils_1.raiseGenerator)('01').encode('hex', false) + this.data.publicKey + this.t + verifierRequest.r), 'hex', 'be')).mod((0, utils_1.getModulus)()).toString('hex');
        const y = new bn_js_1.BN(this.v, 'hex', 'be').add(new bn_js_1.BN(this.e, 'hex', 'be').mul(new bn_js_1.BN(this.data.secret, 'hex', 'be'))).toString('hex');
        return {
            y,
            t: this.t,
            e: this.e
        };
    }
}
exports.FA3FSProver = FA3FSProver;
class FA3FSVerifier {
    constructor(data) {
        this.testedPublicKey = data.testedPublicKey;
    }
    getVerifierRequest() {
        if (this.r) {
            throw new Error("Already generated r");
        }
        this.r = (0, utils_1.randomScalar)();
        return {
            r: this.r
        };
    }
    verify(proverResponse) {
        if (!this.testedPublicKey) {
            throw new Error("No e");
        }
        // 1. Check that e was calculated correctly
        const expectedE = new bn_js_1.BN((0, sha256_1.default)((0, utils_1.raiseGenerator)('01').encode('hex', false) + this.testedPublicKey + proverResponse.t + this.r), 'hex', 'be').mod((0, utils_1.getModulus)()).toString('hex');
        if (expectedE !== proverResponse.e) {
            // E was invalid
            return false;
        }
        const gToY = (0, utils_1.raiseGenerator)(proverResponse.y);
        const gToR = (0, utils_1.parsePoint)(proverResponse.t);
        const publicKey = (0, utils_1.parsePoint)(this.testedPublicKey);
        return gToY.eq(gToR.add(publicKey.mul(new bn_js_1.BN(expectedE, 'hex', 'be'))));
    }
}
exports.FA3FSVerifier = FA3FSVerifier;
class FA3FSProtocol {
    newVerifier(verifierParams) {
        return new FA3FSVerifier(verifierParams);
    }
    newProver(proverParams) {
        return new FA3FSProver(proverParams);
    }
    getRandomProverParams() {
        const randomKeyPair = (0, utils_1.ellipticCurvePair)();
        return {
            secret: randomKeyPair.getPrivate('hex'),
            publicKey: randomKeyPair.getPublic(false, 'hex')
        };
    }
}
exports.FA3FSProtocol = FA3FSProtocol;
