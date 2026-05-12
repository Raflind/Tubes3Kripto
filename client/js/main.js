import {
  generateKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPrivateKey,
  importPublicKey,
  deriveAESKey,
  deriveSharedKey,
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
      loadContacts();
    } catch (err) {
      console.error(err);
      alert("Login failed: Could not decrypt private key.");
    }
  } else {
    alert(result.error);
  }
}

async function selectContact(contact) {
  activeContact = contact.email;

  document.getElementById("empty-chat").style.display = "none";
  document.getElementById("active-chat").style.display = "flex";
  document.getElementById("chatting-with").innerText = contact.email;
  document.getElementById("message-display").innerHTML = "";

  try {
    await _sessionKeys(contact);
    await _loadMessages();
  } catch (err) {
    console.error("Key exchange failed:", err);
    alert("Could not establish secure session with this contact.");
  }
}

// Sending Message (masih placeholder)
async function sendMessage() {
  const input = document.getElementById("msg-input");
  const plaintext = input.value.trim();
  if (!plaintext) return;
  if (!activeSessionKeys) {
    alert("Secure session not established yet. Please wait.");
    return;
  }
  try {
    const payload = await encryptAndSign(
      plaintext,
      activeSessionKeys.aesKey,
      activeSessionKeys.hmacKey,
    );
    const token = localStorage.getItem("jwt_token");
    const response = await fetch("/send-message", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        to: activeContact,
        iv: payload.iv,
        ciphertext: payload.ciphertext,
        mac: payload.mac,
      }),
    });

    if (response.ok) {
      input.value = "";
      _appendBubble(plaintext, "sent");
    } else {
      alert("Failed to send message.");
    }
  } catch (err) {
    console.error("Encryption error:", err);
    alert("Encryption failed.");
  }
}

function handleLogout() {
  if (confirm("Are you sure you want to logout?")) {
    localStorage.removeItem("my_email");
    localStorage.removeItem("jwt_token");
    localStorage.removeItem("my_private_key");
    document.getElementById("active-chat").style.display = "none";
    document.getElementById("empty-chat").style.display = "flex";
    document.getElementById("message-display").innerHTML = "";
    activeContact = null;
    activeSessionKeys = null;
    clearInputs();
    document.getElementById("auth-container").style.display = "flex";
    document.getElementById("chat-app").style.display = "none";
  }
}

function clearInputs() {
  const inputs = document.querySelectorAll("input");
  inputs.forEach((input) => {
    input.value = "";
  });
}

async function loadContacts() {
  const token = localStorage.getItem("jwt_token");
  if (!token) return;

  try {
    const response = await fetch("/get-contacts", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const result = await response.json();

    if (result.success) {
      renderContacts(result.contacts);
    }
    if (response.status === 401) {
      handleLogout();
      return;
    }
  } catch (err) {
    console.error("Failed to load contacts:", err);
  }
}

function renderContacts(contacts) {
  const container = document.getElementById("contact-list-container");
  if (!container) return;

  container.innerHTML = "";

  contacts.forEach((contact) => {
    const item = document.createElement("div");
    item.className = "contact-item";
    item.onclick = () => selectContact(contact);
    const contactUsername = contact.email.split('@')[0];

    item.innerHTML = `
            <div class="contact-info">
                <span class="name">${contact.email}</span>
                <span class="last-msg">Click here to message ${contactUsername}</span>
            </div>
        `;
    container.appendChild(item);
  });
}

function checkAuth() {
  const token = localStorage.getItem("jwt_token");

  if (token) {
    document.getElementById("auth-container").style.display = "none";
    document.getElementById("chat-app").style.display = "flex";
    loadContacts();
  } else {
    document.getElementById("auth-container").style.display = "flex";
    document.getElementById("chat-app").style.display = "none";
  }
}

async function _sessionKeys(receiver) {
  const token = localStorage.getItem("jwt_token");
  const email = localStorage.getItem("my_email");
  const b64privatekey = localStorage.getItem("my_private_key");
  const b64publickey = receiver.publickey;
  const privatekey = await importPrivateKey(b64privatekey);
  const publickey = await importPublicKey(b64publickey);

  const sharedkey = await deriveSharedKey(privatekey, publickey);
  const saltinput = [email, receiver.email].sort().join("|");
  const salt = new TextEncoder().encode(saltinput);

  activeSessionKeys = await deriveAESKey(sharedkey, salt);
}

async function _loadMessages() {
  if (!activeSessionKeys) return;

  const token = localStorage.getItem("jwt_token");
  const response = await fetch("/get-messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ with: activeContact }),
  });

  if (!response.ok) return;
  const { messages } = await response.json();

  const myEmail = localStorage.getItem("my_email");
  const display = document.getElementById("message-display");
  display.innerHTML = "";

  for (const msg of messages) {
    try {
      const plaintext = await verifyAndDecrypt(
        { iv: msg.iv, ciphertext: msg.ciphertext, mac: msg.mac },
        activeSessionKeys.aesKey,
        activeSessionKeys.hmacKey,
      );
      const direction = msg.from === myEmail ? "sent" : "received";
      _appendBubble(plaintext, direction);
    } catch {
      _appendBubble("error");
    }
  }
}
function _appendBubble(text, direction) {
  const display = document.getElementById("message-display");
  const msgWrapper = document.createElement("div");
  const email = direction === "sent" 
    ? localStorage.getItem("my_email") 
    : activeContact;
  const username = email ? email.split('@')[0] : "Unknown";
  msgWrapper.className = `message-wrapper ${direction}`;
  msgWrapper.innerHTML = `
    <div class="message-content">
      <span class="message-username">${username}</span>
      <div class="msg-bubble">${text}</div>
    </div>
  `;
  
  display.appendChild(msgWrapper);
  display.scrollTop = display.scrollHeight;
}

let activeSessionKeys = null;
let activeContact = null;

document.addEventListener("DOMContentLoaded", () => {
  checkAuth();
});
window.handleRegister = handleRegister;
window.handleLogin = handleLogin;
window.handleLogout = handleLogout;
window.sendMessage = sendMessage;
window.toggleForm = toggleForm;
