import {
  constants,
  kdf,
  modPow,
  randomBigInt,
  generateSalt,
} from "./helpers.mjs";
const { g, p, q } = constants;

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
    this.session.r = randomBigInt(q);
    this.session.A = modPow(g, this.session.r, p); // A = g^r mod p
    return this.session.A;
  }

  // Step 5: Response
  response(password, salt, c) {
    // Compute x from the password and salt
    const x = kdf(password, salt); // x = KDF(password, salt)
    // s = r + c * x mod q
    const s = (this.session.r + c * x) % q;
    return s;
  }
}

export { Client };
export default Client;
