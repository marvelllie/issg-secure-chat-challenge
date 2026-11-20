const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto");

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

// Generate pasangan kunci RSA untuk client ini
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

let targetUsername = "";
let username = "";
const users = new Map();

socket.on("connect", () => {
  console.log("Connected to the server");

  rl.question("Enter your username: ", (input) => {
    username = input;
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
        if ((match = message.match(/^!secret (\w+)$/))) {
          const target = match[1];
          if (!users.has(target)) {
            console.log(`User "${target}" not found in chat.`);
          } else {
            targetUsername = target;
            console.log(`Now secretly chatting with ${targetUsername}`);
          }
        } else if (message.match(/^!exit$/)) {
          console.log(`No more secretly chatting with ${targetUsername}`);
          targetUsername = "";
        } else {
          if (targetUsername) {
            // Enkripsi pesan menggunakan publicKey milik targetUsername
            const targetPublicKeyPem = users.get(targetUsername);
            const targetPublicKey = crypto.createPublicKey(targetPublicKeyPem);
            const encryptedMessage = crypto
              .publicEncrypt(targetPublicKey, Buffer.from(message))
              .toString("hex");

            socket.emit("message", {
              username,
              message: encryptedMessage,
              targetUsername,
            });
          } else {
            // Kirim pesan biasa (public chat)
            socket.emit("message", {
              username,
              message,
              targetUsername: "",
            });
          }
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
    targetUsername: msgTarget,
  } = data;

  if (senderUsername !== username) {
    if (msgTarget) {
      // Jika pesan ini ditujukan khusus untuk saya
      if (msgTarget === username) {
        try {
          const decryptedBuffer = crypto.privateDecrypt(
            privateKey,
            Buffer.from(senderMessage, "hex")
          );
          console.log(
            `${senderUsername} (Secret): ${decryptedBuffer.toString("utf8")}`
          );
        } catch (err) {
          console.log(`${senderUsername} (Failed to decrypt): ${senderMessage}`);
        }
      } else {
        // User lain hanya melihat ciphertext acak (gibberish)
        console.log(`${senderUsername}: ${senderMessage}`);
      }
    } else {
      // Pesan publik biasa
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