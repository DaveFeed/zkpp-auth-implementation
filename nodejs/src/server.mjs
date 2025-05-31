import {
  randomBigInt,
  modPow,
  constants,
  hash,
  log,
  bigIntToStringShort,
} from "./helpers.mjs";
const { g, p, q, k } = constants;

class Server {
  constructor() {
    this.clients = {};
    this.sessions = {};
  }

  storeData(username, { V, salt }) {
    if (this.clients[username]) {
      console.log(`User ${username} already exists.`);
      return;
    }

    this.clients[username] ??= {};
    this.clients[username].V = V;
    this.clients[username].salt = salt;
  }

  challenge(username, A) {
    if (!this.clients[username]) {
      throw new Error("User not found: " + username);
    }

    this.sessions[username] ??= {};
    this.sessions[username].A = A;
    this.sessions[username].b = randomBigInt(q); // [0, q)
    log(
      `Server: Generated b = ${bigIntToStringShort(this.sessions[username].b)}`
    );

    this.sessions[username].B =
      k * this.clients[username].V + modPow(g, this.sessions[username].b, p); // B = kV + g^b
    log(
      `Server: Generated B = ${bigIntToStringShort(this.sessions[username].B)}`
    );
    return { salt: this.clients[username]?.salt, B: this.sessions[username].B };
  }

  calculateKey(username) {
    if (!this.sessions[username]) {
      throw new Error("Session not found for user: " + username);
    }
    const session = this.sessions[username];

    const Ss = modPow(
      session.A * this.clients[username].V,
      session.b,
      p
    ); // Ss = (A * V)^b mod p
    log(`Server: Computed Sc = ${bigIntToStringShort(Ss)}`);
    const Ks = hash(Ss); // Ks = H(Ss)
    log(`Server: Computed Kc = ${Ks}`);
    session.Ks = Ks; // Store Ks for later in signing
  }

  hello(username) {
    return this.sign(username, "Hello!");
  }

  sign(username, message) {
    if (!this.sessions[username]) {
      throw new Error("Session not found for user: " + username);
    }
    const session = this.sessions[username];
    return {
      message,
      signature: hash(session.A, session.Ks, message),
    };
  }

  verify(username, payload) {
    if (!this.sessions[username]) {
      throw new Error("Session not found for user: " + username);
    }
    const { message, signature } = payload || {};
    const expectedSignature = hash(
      hash(username),
      this.sessions[username].B,
      this.sessions[username].Ks,
      message
    );

    if (signature === expectedSignature) {
      log(`Server: Signature verified for message: ${message}`);
      return true;
    } else {
      log(`Server: Signature verification failed for message: ${message}`);
      return false;
    }
  }
}

export { Server };
export default Server;
