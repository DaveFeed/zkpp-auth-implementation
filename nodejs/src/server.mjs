import { randomBigInt, modPow, constants } from "./helpers.mjs";
const { g, p, q } = constants;

class Server {
  constructor() {
    this.clients = {};
    this.session = {};
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

  getSalt(username) {
    return this.clients[username]?.salt;
  }

  // Step 4: Issue challenge
  challenge(username, A) {
    this.session[username] ??= {};
    this.session[username].A = A;
    this.session[username].c = randomBigInt(q); // [0, q)
    return this.session[username].c;
  }

  // Step 6: Verify response
  verify(username, s) {
    // g^s ?= A * V^c mod p
    const lhs = modPow(g, s, p);
    const rhs =
      (this.session[username].A *
        modPow(this.clients[username].V, this.session[username].c, p)) %
      p;
    if (lhs === rhs) {
      return 0;
    }
    return 1;
  }
}

export { Server };
export default Server;
