/*
 * The protocol is based on the Diffie-Hellman key exchange and uses a
 * password-based key derivation function (PBKDF) to derive a secret value
 * from the password and a random salt. The verifier is stored on the server,
 * and the client computes a commitment and response to authenticate itself.
 *
 * The protocol is secure against offline dictionary attacks and does not
 * require the server to store the password in plaintext. The use of a random
 * salt ensures that the same password will yield different verifiers for
 * different users, making it difficult for an attacker to use precomputed
 * tables (rainbow tables) to crack the password.
 *
 * Terms used:
 *   - p: large prime number
 *   - g: generator of the group
 *   - x: secret value (password)
 *   - V: verifier (g^x mod p)
 *   - A: commitment (g^r mod p)
 *   - r: random value (client secret)
 *   - s: response (r + c * x mod q)
 *   - c: challenge (random value)
 *   - q: safe prime (p-1)/2
 *   - kdf: key derivation function
 */
import Client from "./src/client.mjs";
import Server from "./src/server.mjs";
import readline from "readline";
const transport = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

function log(message) {
  if (process.env?.npm_lifecycle_event === "test") {
    return;
  }

  console.log(message);
}

/*
 * Protocol Steps:
 * 1. Client generates a random salt and computes the verifier "V" from the password and salt (x).
 * 2. Server stores the salt and verifier "V".
 * 3. Client generates a random value "r" and computes the commitment "A".
 * 4. Server issues a challenge "c".
 * 5. Client computes the response "s" using the challenge "c" and the secret value "x".
 * 6. Server verifies the response by checking if g^s == A * V^c mod p.
 */

const server = new Server();
const client = new Client("username");

let createdPassword = "";
await new Promise((resolve) => {
  transport.question("Create Password: ", (input) => {
    createdPassword = input;
    resolve();
  });
});

server.storeData(client.username, client.register(createdPassword));
log(`Verifier: ${server.clients[client.username].V}`);
log(`Salt: ${server.clients[client.username].salt}`);

let password = "";
await new Promise((resolve) => {
  transport.question("Enter password: ", (input) => {
    password = input;
    resolve();
  });
});
const salt = server.getSalt(client.username);

const commitment = client.commit();
const challenge = server.challenge(client.username, commitment);
log(`Commitment: ${commitment}`);
log(`Challenge: ${challenge}`);

const response = client.response(password, salt, challenge);
const statusCode = server.verify(client.username, response);

log(`Response: ${response}`);
log(`Status Code: ${statusCode}`);

transport.close();
if (process.env?.npm_lifecycle_event !== "test") {
  if (statusCode === 0) {
    console.log("✅ Authentication successful.");
  } else {
    console.log("❌ Authentication failed.");
  }
} else {
  process.exit(statusCode);
}
