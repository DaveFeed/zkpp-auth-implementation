import {
  constants,
  kdf,
  modPow,
  randomBigInt,
  generateSalt,
  hash,
  log,
  bigIntToStringShort,
} from "./helpers.mjs";
const { g, p, q, k } = constants;

class Client {
  constructor(username) {
    this.session = {};
    this.username = username;
  }

  register(password) {
    if (!password) {
      throw new Error("Password is required for registration.");
    }

    const salt = generateSalt();
    log(`Client: Generated salt = ${salt}`);
    const x = kdf(password, salt); // x = KDF(password, salt)
    const V = modPow(g, x, p); // V = g^x mod p
    log(`Client: Generated V = ${bigIntToStringShort(V)}`);
    return { V, salt };
  }

  commit() {
    this.session.a = randomBigInt(q);
    log(`Client: Generated a = ${bigIntToStringShort(this.session.a)}`);
    this.session.A = modPow(g, this.session.a, p); // A = g^a mod p
    log(`Client: Generated A = ${bigIntToStringShort(this.session.A)}`);
    return this.session.A;
  }

  calculateKey(password, salt, B) {
    // Compute x from the password and salt
    const x = kdf(password, salt); // x = KDF(password, salt)
    log(`Client: Computed x = ${bigIntToStringShort(x)}`);

    const Sc = modPow(B - k * modPow(g, x, p), this.session.a + x, p); // Sc = (B - k * g^x mod p)^(a + x) mod p
    log(`Client: Computed Sc = ${bigIntToStringShort(Sc)}`);
    const Kc = hash(Sc); // Kc = H(Sc)
    log(`Client: Computed Kc = ${Kc}`);

    this.session.B = B; // Store B for later in signing
    this.session.Kc = Kc;
  }

  hello() {
    return this.sign("Hello!");
  }

  sign(message) {
    if (!this.session.Kc) {
      throw new Error(
        "Key not generated. Please complete the authentication process first."
      );
    }
    const signature = hash(
      hash(this.username),
      this.session.B,
      this.session.Kc,
      message
    );
    return {
      message,
      signature: signature,
    };
  }

  verify(payload) {
    if (!this.session.Kc) {
      throw new Error(
        "Key not generated. Please complete the authentication process first."
      );
    }
    const { message, signature } = payload || {};
    const expectedSignature = hash(this.session.A, this.session.Kc, message);

    if (signature === expectedSignature) {
      log(`Client: Signature verified for message: ${message}`);
      return true;
    } else {
      log(`Client: Signature verification failed for message: ${message}`);
      return false;
    }
  }
}

export { Client };
export default Client;
