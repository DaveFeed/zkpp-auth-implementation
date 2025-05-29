import Client from "./src/client.mjs";
import { log } from "./src/helpers.mjs";
import Server from "./src/server.mjs";
import readline from "readline";
const transport = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

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

let password = "";
await new Promise((resolve) => {
  transport.question("Enter password: ", (input) => {
    password = input;
    resolve();
  });
});
transport.close();

const A = client.commit();
const { B, salt } = server.challenge(client.username, A);

client.calculateKey(password, salt, B);
server.calculateKey(client.username);

// Cross validate the keys
const clientVerificationRequest = client.hello();
const clientVerificationResponse = server.verify(client.username, clientVerificationRequest);

if(!clientVerificationResponse) {
  log("❌ Client verification failed.");
  process.exit(1);
}

const serverVerificationRequest = server.hello(client.username);
const serverVerificationResponse = client.verify(serverVerificationRequest);

if(!serverVerificationResponse) {
  log("❌ Server verification failed.");
  process.exit(1);
}

log("✅ Client and server verification successful.");
process.exit(0);
