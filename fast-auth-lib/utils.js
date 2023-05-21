"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateSHA256Hash = exports.parsePoint = exports.getModulus = exports.raiseGenerator = exports.randomScalar = exports.ellipticCurvePair = void 0;
const elliptic_1 = require("elliptic");
const secp256k1EllipticCurve = new elliptic_1.ec('secp256k1');
const crypto = require('crypto');
function ellipticCurvePair() {
    return secp256k1EllipticCurve.genKeyPair();
}
exports.ellipticCurvePair = ellipticCurvePair;
function randomScalar() {
    return secp256k1EllipticCurve.genKeyPair().getPrivate().toString('hex');
}
exports.randomScalar = randomScalar;
function raiseGenerator(scalar) {
    return secp256k1EllipticCurve.g.mul(scalar);
}
exports.raiseGenerator = raiseGenerator;
function getModulus() {
    return secp256k1EllipticCurve.curve.n;
}
exports.getModulus = getModulus;
function parsePoint(point) {
    return secp256k1EllipticCurve.keyFromPublic(point, 'hex').getPublic(); // Deserialize public key from hexadecimal format
}
exports.parsePoint = parsePoint;
function generateSHA256Hash(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}
exports.generateSHA256Hash = generateSHA256Hash;
