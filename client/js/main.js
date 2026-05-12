// Navigasi Log/Reg
import {
  generateKeyPair,
  exportPublicKey,
  exportPrivateKey,
  generateStorageKey,
} from "./crypto/ecdh.js";

import {
  encryptAndSign,
  _bufferToBase64,
  _base64ToArrayBuffer,
  verifyAndDecrypt,
} from "./crypto/aes_hmac.js";

function toggleForm(type) {
  const loginForm = document.getElementById("login-form");
  const regForm = document.getElementById("register-form");
  if (type === "login") {
    clearInputs();
    regForm.classList.remove("active");
    loginForm.classList.add("active");
  } else {
    clearInputs();
    loginForm.classList.remove("active");
    regForm.classList.add("active");
  }
}

// Register (masih placeholder)
export async function handleRegister() {
  const email = document.getElementById("reg-email").value;
  const password = document.getElementById("reg-pass").value;
  if (!email || !password) {
    alert("Please fill email and password!");
    return;
  }
  // console.log("Registered:", email);
  const keyPair = await generateKeyPair();
  const publickey = await exportPublicKey(keyPair.publicKey);
  const privatekey = await exportPrivateKey(keyPair.privateKey);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { aesKey, hmacKey } = await generateStorageKey(password, salt);
  const encrypted = await encryptAndSign(privatekey, aesKey, hmacKey);

  const response = await fetch("/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: email,
      password: password,
      publickey: publickey,
      privatekey: encrypted.ciphertext,
      salt: _bufferToBase64(salt),
      iv: encrypted.iv,
      mac: encrypted.mac,
    }),
  });

  if (response.ok) (alert("Registration Berhasil!"), toggleForm("login"));
  else alert("Register Gagal!");
}

// Login (masih placeholder)
async function handleLogin() {
  const email = document.getElementById("login-email").value;
  const password = document.getElementById("login-pass").value;
  const response = await fetch("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });

  const result = await response.json();

  if (response.ok) {
    const user = result.user;
    const saltBuffer = new Uint8Array(_base64ToArrayBuffer(user.salt));
    const { aesKey, hmacKey } = await generateStorageKey(password, saltBuffer);
    try {
      const privateKey = await verifyAndDecrypt(
        {
          iv: user.iv,
          ciphertext: user.encryptedPrivateKey,
          mac: user.mac,
        },
        aesKey,
        hmacKey,
      );
      localStorage.setItem("my_email", result.user.email);
      localStorage.setItem("jwt_token", result.token);
      localStorage.setItem("my_private_key", privateKey);

      alert("Login Successful!");
      document.getElementById("auth-container").style.display = "none";
      document.getElementById("chat-app").style.display = "flex";
    } catch (err) {
      console.error(err);
      alert("Login failed: Could not decrypt private key.");
    }
  } else {
    alert(result.error);
  }
}

// Contact Selection (masih placeholder)
function selectContact(name) {
  document.getElementById("empty-chat").style.display = "none";
  document.getElementById("active-chat").style.display = "flex";
  document.getElementById("chatting-with").innerText = name;

  // placeholder for key exchange
}

// Sending Message (masih placeholder)
function sendMessage() {
  const input = document.getElementById("msg-input");
  const msg = input.value;
  if (!msg) return;
  const display = document.getElementById("message-display");
  const div = document.createElement("div");
  div.className = "bubble sent";
  div.innerText = msg;
  display.appendChild(div);
  display.scrollTop = display.scrollHeight;

  // AES encrypt

  input.value = "";
}

// Logout (masih placeholder)
function handleLogout() {
  if (confirm("Are you sure you want to logout?")) {
    clearInputs();
    document.getElementById("auth-container").style.display = "flex";
    document.getElementById("chat-app").style.display = "none";

    // placeholder to remove private key
    // activePrivateKey = null;
  }
}

function clearInputs() {
  const inputs = document.querySelectorAll("input");
  inputs.forEach((input) => {
    input.value = "";
  });
}

async function decryptPrivateKey(encrypted_pk, password, saltStr) {
  const salt = _base64ToArrayBuffer(saltStr);
  const { aesKey, hmacKey } = await getStorageKey(password, salt);
  const privateKeyStr = await decryptAndVerify(
    encrypted_pk.ciphertext,
    encrypted_pk.iv,
    encrypted_pk.mac,
    aesKey,
    hmacKey,
  );
  return privateKeyStr;
}

window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.toggleForm = toggleForm;
