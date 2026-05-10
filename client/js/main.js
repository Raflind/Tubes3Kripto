// Navigasi Log/Reg
function toggleForm(type) {
    const loginForm = document.getElementById('login-form');
    const regForm = document.getElementById('register-form');
    if (type === 'login') {
        clearInputs();
        regForm.classList.remove('active');
        loginForm.classList.add('active');
    } else {
        clearInputs();
        loginForm.classList.remove('active');
        regForm.classList.add('active');
    }
}

// Register (masih placeholder)
async function handleRegister() {
    const email = document.getElementById('reg-email').value;
    const pass = document.getElementById('reg-pass').value;
    if (!email || !pass) {
        alert("Please fill email and password!");
        return;
    }
    // console.log("Registered:", email);

    // placeholder for Keys Geneartion 
    
    alert("Registration Success!");
    toggleForm('login');
}

// Login (masih placeholder)
async function handleLogin() {
    const email = document.getElementById('login-email').value;
    const pass = document.getElementById('login-pass').value;
    if (!email || !pass) {
        alert("Please fill email and password!");
        return;
    }

    // placeholder for keys fetching and decryption to use after log in
    clearInputs();
    const authContainer = document.getElementById('auth-container');
    const chatApp = document.getElementById('chat-app');
    if (authContainer && chatApp) {
        authContainer.style.display = 'none';
        chatApp.style.display = 'flex';     
        console.log("Logged in as:", email);
    } else {
        console.error("Error: Container ID not found!");
    }
}

// Contact Selection (masih placeholder)
function selectContact(name) {
    document.getElementById('empty-chat').style.display = 'none';
    document.getElementById('active-chat').style.display = 'flex';
    document.getElementById('chatting-with').innerText = name;

    // placeholder for key exchange
}

// Sending Message (masih placeholder)
function sendMessage() {
    const input = document.getElementById('msg-input');
    const msg = input.value;
    if (!msg) return;
    const display = document.getElementById('message-display');
    const div = document.createElement('div');
    div.className = 'bubble sent';
    div.innerText = msg;
    display.appendChild(div);
    display.scrollTop = display.scrollHeight;

    // AES encrypt
    
    input.value = '';
}

// Logout (masih placeholder)
function handleLogout() {
    if (confirm("Are you sure you want to logout?")) {
        clearInputs();
        document.getElementById('auth-container').style.display = 'flex';
        document.getElementById('chat-app').style.display = 'none';
        
        // placeholder to remove private key
        // activePrivateKey = null;
    }
}

function clearInputs() {
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.value = '';
    });
}