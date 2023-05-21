import { ec as EC, curve } from 'elliptic';

const secp256k1EllipticCurve = new EC('secp256k1');
const crypto = require('crypto');


export function ellipticCurvePair() {
    return secp256k1EllipticCurve.genKeyPair();
}

export function randomScalar() {
    return secp256k1EllipticCurve.genKeyPair().getPrivate().toString('hex');
}

export function raiseGenerator(scalar: string) {
    return secp256k1EllipticCurve.g.mul(scalar) as curve.base.BasePoint;
}

export function getModulus() {
    return secp256k1EllipticCurve.curve.n;
}

export function parsePoint(point: string) {
    return secp256k1EllipticCurve.keyFromPublic(point, 'hex').getPublic(); // Deserialize public key from hexadecimal format

}

export function generateSHA256Hash(data: string) {
  const hash = crypto.createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}
