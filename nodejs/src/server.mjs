import { randomBigInt, modPow, constants, hash, log, bigIntToStringShort } from "./helpers.mjs";
const { g, p, q, k } = constants;

class Server {
  constructor() {
    this.clients = {};
    this.sessions = {};
  }

  // Step 2: Store verifier and salt (optional)
  storeData(username, { V, salt }) {
    if (this.clients[username]) {
      console.log(`User ${username} already exists.`);
      return;
    }

    this.clients[username] ??= {};
    this.clients[username].V = V;
    this.clients[username].salt = salt;
  }

  // Step 4: Issue challenge
  challenge(username, A) {
    this.sessions[username] ??= {};
    this.sessions[username].A = A;
    this.sessions[username].b = randomBigInt(q); // [0, q)
    log(`Server: Generated b = ${bigIntToStringShort(this.sessions[username].b)}`);

    this.sessions[username].B = k*this.clients[username].V +
      modPow(g, this.sessions[username].b, p); // B = kV + g^b
    log(`Server: Generated B = ${bigIntToStringShort(this.sessions[username].B)}`);
    return { salt: this.clients[username]?.salt, B: this.sessions[username].B };
  }

  // Step 6: Verify response
  generateKey(username) {
    const u = hash(this.sessions[username].A, this.sessions[username].B); // u = H(A, B)
    log(`Server: Computed u = ${u}`);

    const Ss = modPow(this.sessions[username].A * modPow(this.clients[username].V, u, p), this.sessions[username].b, p); // Ss = A * V^b mod p
    log(`Server: Computed Sc = ${bigIntToStringShort(Ss)}`);
    const Ks = hash(Ss); // Ks = H(Ss)
    log(`Server: Computed Kc = ${Ks}`);
    this.sessions[username].Ks = Ks; // Store Ks for later in signing

    return Ks;
  }

  hello(username) {
    return this.sign(username, "Hello!");
  }

  sign(username, message) {
    if (!this.sessions[username]) {
      throw new Error("Session not found for user: " + username);
    }

    const signature = hash(this.sessions[username].A, this.sessions[username].Ks, message);
    return {
      message,
      signature: signature,
    };
  }

  verify(username, payload) {
    if (!this.sessions[username]) {
      throw new Error("Session not found for user: " + username);
    }

    const { message, signature } = (payload || {});
    const expectedSignature = hash(hash(username), this.sessions[username].B, this.sessions[username].Ks, message);

    if (signature === expectedSignature) {
      log(`Server: Signature verified for message:: ${message}`);
      return true;
    } else {
      log(`Server: Signature verification failed for message: ${message}`);
      return false;
    }
  }
}

export { Server };
export default Server;
