const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

// Generate RSA key pair untuk client ini
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

let registeredUsername = "";
let username = "";
const users = new Map();

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
    registeredUsername = input;
    console.log(`Welcome, ${username} to the chat`);

    // Daftarkan public key asli milik user ke server
    socket.emit("registerPublicKey", {
      username,
      publicKey,
    });
    rl.prompt();

    rl.on("line", (message) => {
      if (message.trim()) {
        let match;
        if ((match = message.match(/^!impersonate (\w+)$/))) {
          username = match[1];
          console.log(`Now impersonating as ${username}`);
        } else if (message.match(/^!exit$/)) {
          username = registeredUsername;
          console.log(`Now you are ${username}`);
        } else {
          // Tandatangani pesan menggunakan privateKey milik pengirim
          const signature = crypto
            .sign("sha256", Buffer.from(message), privateKey)
            .toString("hex");
          socket.emit("message", { username, message, signature });
        }
      }
      rl.prompt();
    });
  });
});

socket.on("init", (keys) => {
  keys.forEach(([user, key]) => users.set(user, key));
  console.log(`\nThere are currently ${users.size} users in the chat`);
  rl.prompt();
});

socket.on("newUser", (data) => {
  const { username: newUsername, publicKey: newPublicKey } = data;
  users.set(newUsername, newPublicKey);
  console.log(`${newUsername} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const {
    username: senderUsername,
    message: senderMessage,
    signature: senderSignature,
  } = data;

  // Abaikan pesan yang memang dikirim oleh diri sendiri
  if (senderUsername !== registeredUsername || senderSignature) {
    const senderPublicKeyPem = users.get(senderUsername);

    // Cek apakah public key pengirim ada dan tanda tangan valid
    let isVerified = false;
    if (senderPublicKeyPem && senderSignature) {
      try {
        const senderPublicKey = crypto.createPublicKey(senderPublicKeyPem);
        isVerified = crypto.verify(
          "sha256",
          Buffer.from(senderMessage),
          senderPublicKey,
          Buffer.from(senderSignature, "hex")
        );
      } catch (err) {
        isVerified = false;
      }
    }

    // Jangan tampilkan ulang pesan asli milik diri sendiri yang valid
    if (senderUsername === registeredUsername && isVerified) {
      return;
    }

    if (!isVerified) {
      console.log(`\n[WARNING] This user is fake! Impersonation detected for "${senderUsername}"!`);
      console.log(`${senderUsername} (FAKE): ${senderMessage}`);
    } else {
      console.log(`${senderUsername}: ${senderMessage}`);
    }
    rl.prompt();
  }
});

socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});