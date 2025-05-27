import {
  constants,
  kdf,
  modPow,
  randomBigInt,
  generateSalt,
  hash,
} from "./helpers.mjs";
const { g, p, q, k } = constants;

class Client {
  constructor(username) {
    this.session = {};
    this.username = username;
  }

  // Step 1: Registration
  register(password) {
    if (!password) {
      throw new Error("Password is required for registration.");
    }

    const salt = generateSalt();
    const x = kdf(password, salt); // x = KDF(password, salt)
    const V = modPow(g, x, p); // V = g^x mod p
    return { V, salt };
  }

  // Step 3: Commitment
  commit() {
    this.session.a = randomBigInt(q);
    this.session.A = modPow(g, this.session.a, p); // A = g^a mod p
    return this.session.A;
  }

  // Step 5: Response
  generateKey(password, salt, B) {
    // Compute x from the password and salt
    const x = kdf(password, salt); // x = KDF(password, salt)

    const u = hash(this.session.A, B); // u = H(A, B)
    // s = a + c * x mod q
    // const s = (this.session.a + c * x) % q;
    const Sc = modPow((B - k * modPow(g, x, p)), this.session.a + u * x, p); // Sc = (B - k * g^x mod p)^(a + u*x) mod p
    const Kc = hash(Sc);

    return Kc; // Kc = H(Sc)
  }
}

export { Client };
export default Client;
