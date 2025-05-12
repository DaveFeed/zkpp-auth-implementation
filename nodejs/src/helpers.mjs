import { randomBytes, createHash, pbkdf2Sync } from "crypto";

/*
 * Source: https://www.ietf.org/rfc/rfc3526.txt
 * Group 14: 2048-bit MODP Group
 */
const p_hex = `
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF`.replace(/\s+/g, "");
const p = BigInt("0x" + p_hex);
const g = 2n;
const q = (p - 1n) / 2n;

function randomBigInt(max) {
  const byteLength = (max.toString(2).length + 7) >> 3;
  let rand;
  do {
    rand = BigInt("0x" + randomBytes(byteLength).toString("hex"));
  } while (rand >= max);
  return rand;
}

// Modular exponentiation
function modPow(base, exponent, modulus) {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1n;
    base = (base * base) % modulus;
  }
  return result;
}

// Print BigInt as hex
function printBigInt(label, val) {
  console.log(`${label} = 0x${val.toString(16)}`);
}

function generateSalt() {
  const salt = randomBytes(16).toString("hex");
  return salt;
}

function kdf(password, salt, iterations = 100_000, dklen = 32, digest = "sha256") {
  const hash = pbkdf2Sync(password, salt, iterations, dklen, digest); // 100k iterations
  return BigInt("0x" + hash.toString("hex"));
}

const constants = {
  p,
  g,
  q,
};

export {
  constants,
  randomBigInt,
  modPow,
  printBigInt,
  generateSalt,
  kdf,
};
