import { randomBigInt, modPow, constants, hash } from "./helpers.mjs";
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
    this.sessions[username].B = k*this.clients[username].V + // todo:: check if modPow is needed here
      modPow(g, this.sessions[username].b, p); // B = k*V + g^b
    return { salt: this.clients[username]?.salt, B: this.sessions[username].B };
  }

  // Step 6: Verify response
  generateKey(username) {
    const u = hash(this.sessions[username].A, this.sessions[username].B); // u = H(A, B)

    const Sc = modPow(this.sessions[username].A * modPow(this.clients[username].V, u, p), this.sessions[username].b, p); // Sc = A * V^b mod p
    const Kc = hash(Sc); // Kc = H(Sc)

    return Kc;
  }
}

export { Server };
export default Server;
