
function caesarCipher(s, k) {
  let result = '';
  k = k % 26;
  for (let i = 0; i < s.length; i++) {
    let charCode = s.charCodeAt(i);
    if (charCode > 96 && charCode < 123) {
      charCode += k;
      if (charCode > 122) charCode = (charCode - 122) + 96;
      else if (charCode < 97) charCode = (charCode - 97) + 123;
    }
    if (charCode > 64 && charCode < 91) {
      charCode += k;
      if (charCode > 90) charCode = (charCode - 90) + 64;
      else if (charCode < 65) charCode = (charCode - 65) + 91;
    }
    result += String.fromCharCode(charCode);
  }
  return result;
}

const ciphers = {
  caesar: {
    category: 'classical',
    needsKey: true,
    keyType: 'number',
    encrypt: (text, key) => caesarCipher(text, parseInt(key)),
    decrypt: (text, key) => caesarCipher(text, -parseInt(key)),
  },
  rot13: {
    category: 'classical',
    needsKey: false,
    keyType: 'none',
    encrypt: (text) => caesarCipher(text, 13),
    decrypt: (text) => caesarCipher(text, 13), // Symmetric
  },
  atbash: {
    category: 'classical',
    needsKey: false,
    keyType: 'none',
    encrypt: (text) => {
      return text.replace(/[a-zA-Z]/g, (c) => {
        const base = c.toLowerCase() === c ? 'a'.charCodeAt(0) : 'A'.charCodeAt(0);
        return String.fromCharCode(25 - (c.charCodeAt(0) - base) + base);
      });
    },
    decrypt: (text) => this.encrypt(text), // Symmetric
  },
  'simple-sub': {
    category: 'classical',
    needsKey: true,
    keyType: 'string', 
    encrypt: (text, key) => {
      if (key.length !== 26) return 'Invalid key: must be 26 unique letters';
      const alphabet = 'abcdefghijklmnopqrstuvwxyz';
      const map = {};
      alphabet.split('').forEach((c, i) => (map[c] = key.toLowerCase()[i]));
      return text.toLowerCase().replace(/[a-z]/g, (c) => map[c] || c);
    },
    decrypt: (text, key) => {
      if (key.length !== 26) return 'Invalid key: must be 26 unique letters';
      const alphabet = 'abcdefghijklmnopqrstuvwxyz';
      const map = {};
      key.toLowerCase().split('').forEach((c, i) => (map[c] = alphabet[i]));
      return text.toLowerCase().replace(/[a-z]/g, (c) => map[c] || c);
    },
  },
  vigenere: {
    category: 'classical',
    needsKey: true,
    keyType: 'string',
    encrypt: (text, key) => {
      key = key.toUpperCase();
      let j = 0;
      return text.toUpperCase().replace(/[A-Z]/g, (c) => {
        const shift = key[j++ % key.length].charCodeAt(0) - 65;
        return String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26) + 65);
      });
    },
    decrypt: (text, key) => {
      key = key.toUpperCase();
      let j = 0;
      return text.toUpperCase().replace(/[A-Z]/g, (c) => {
        const shift = key[j++ % key.length].charCodeAt(0) - 65;
        return String.fromCharCode(((c.charCodeAt(0) - 65 - shift + 26) % 26) + 65);
      });
    },
  },
  playfair: {
    category: 'classical',
    needsKey: true,
    keyType: 'string',
    encrypt: (text, key) => {
      
      key = key.toUpperCase().replace(/J/g, 'I');
      let alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
      let used = new Set();
      let matrix = [];
      for (let c of key + alphabet) {
        if (!used.has(c)) used.add(c);
      }
      let usedArr = Array.from(used);
      for (let i = 0; i < 5; i++) {
        matrix.push(usedArr.slice(i * 5, (i + 1) * 5));
      }
      
      text = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
      let pairs = [];
      for (let i = 0; i < text.length; i += 2) {
        let a = text[i];
        let b = i + 1 < text.length ? text[i + 1] : 'X';
        if (a === b) {
          pairs.push([a, 'X']);
          i--;
        } else {
          pairs.push([a, b]);
        }
      }
      
      let result = '';
      const findPos = (c) => {
        for (let r = 0; r < 5; r++) {
          for (let col = 0; col < 5; col++) {
            if (matrix[r][col] === c) return [r, col];
          }
        }
      };
      for (let [a, b] of pairs) {
        let [r1, c1] = findPos(a);
        let [r2, c2] = findPos(b);
        if (r1 === r2) {
          result += matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5];
        } else if (c1 === c2) {
          result += matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2];
        } else {
          result += matrix[r1][c2] + matrix[r2][c1];
        }
      }
      return result;
    },
    decrypt: (text, key) => {
      
      key = key.toUpperCase().replace(/J/g, 'I');
      let alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
      let used = new Set();
      let matrix = [];
      for (let c of key + alphabet) {
        if (!used.has(c)) used.add(c);
      }
      let usedArr = Array.from(used);
      for (let i = 0; i < 5; i++) {
        matrix.push(usedArr.slice(i * 5, (i + 1) * 5));
      }
      
      text = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
      let pairs = [];
      for (let i = 0; i < text.length; i += 2) {
        pairs.push([text[i], text[i + 1]]);
      }
      
      let result = '';
      const findPos = (c) => {
        for (let r = 0; r < 5; r++) {
          for (let col = 0; col < 5; col++) {
            if (matrix[r][col] === c) return [r, col];
          }
        }
      };
      for (let [a, b] of pairs) {
        let [r1, c1] = findPos(a);
        let [r2, c2] = findPos(b);
        if (r1 === r2) {
          result += matrix[r1][(c1 - 1 + 5) % 5] + matrix[r2][(c2 - 1 + 5) % 5];
        } else if (c1 === c2) {
          result += matrix[(r1 - 1 + 5) % 5][c1] + matrix[(r2 - 1 + 5) % 5][c2];
        } else {
          result += matrix[r1][c2] + matrix[r2][c1];
        }
      }
      return result.replace(/X+$/, ''); // Remove padding
    },
  },
  hill: {
    category: 'classical',
    needsKey: true,
    keyType: 'string', // 4 letters for 2x2 matrix
    encrypt: (text, key) => {
      key = key.toUpperCase();
      if (key.length !== 4) return 'Key must be 4 letters for 2x2 matrix';
      const matrix = [
        [key.charCodeAt(0) - 65, key.charCodeAt(1) - 65],
        [key.charCodeAt(2) - 65, key.charCodeAt(3) - 65],
      ];
      text = text.toUpperCase().replace(/[^A-Z]/g, '');
      if (text.length % 2 !== 0) text += 'X';
      let result = '';
      for (let i = 0; i < text.length; i += 2) {
        const v = [text.charCodeAt(i) - 65, text.charCodeAt(i + 1) - 65];
        const e0 = (matrix[0][0] * v[0] + matrix[0][1] * v[1]) % 26;
        const e1 = (matrix[1][0] * v[0] + matrix[1][1] * v[1]) % 26;
        result += String.fromCharCode(e0 + 65) + String.fromCharCode(e1 + 65);
      }
      return result;
    },
    decrypt: (text, key) => {
      key = key.toUpperCase();
      if (key.length !== 4) return 'Key must be 4 letters for 2x2 matrix';
      const matrix = [
        [key.charCodeAt(0) - 65, key.charCodeAt(1) - 65],
        [key.charCodeAt(2) - 65, key.charCodeAt(3) - 65],
      ];
      let det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26;
      if (det < 0) det += 26;
      let detInv = 0;
      for (let i = 1; i < 26; i++) {
        if ((det * i) % 26 === 1) detInv = i;
      }
      if (!detInv) return 'Key not invertible';
      const invMatrix = [
        [(matrix[1][1] * detInv) % 26, ((-matrix[0][1] + 26) * detInv) % 26],
        [((-matrix[1][0] + 26) * detInv) % 26, (matrix[0][0] * detInv) % 26],
      ];
      text = text.toUpperCase().replace(/[^A-Z]/g, '');
      let result = '';
      for (let i = 0; i < text.length; i += 2) {
        const v = [text.charCodeAt(i) - 65, text.charCodeAt(i + 1) - 65];
        const d0 = (invMatrix[0][0] * v[0] + invMatrix[0][1] * v[1]) % 26;
        const d1 = (invMatrix[1][0] * v[0] + invMatrix[1][1] * v[1]) % 26;
        result += String.fromCharCode(d0 + 65) + String.fromCharCode(d1 + 65);
      }
      return result.replace(/X+$/, '');
    },
  },
  'rail-fence': {
    category: 'transposition',
    needsKey: true,
    keyType: 'number', // Number of rails
    encrypt: (text, key) => {
      key = parseInt(key);
      if (key < 2) return text;
      let rails = Array(key).fill('');
      let dir = 1;
      let row = 0;
      for (let c of text) {
        rails[row] += c;
        row += dir;
        if (row === key - 1 || row === 0) dir = -dir;
      }
      return rails.join('');
    },
    decrypt: (text, key) => {
      key = parseInt(key);
      if (key < 2) return text;
      let railLengths = Array(key).fill(0);
      let dir = 1;
      let row = 0;
      for (let i = 0; i < text.length; i++) {
        railLengths[row]++;
        row += dir;
        if (row === key - 1 || row === 0) dir = -dir;
      }
      let rails = [];
      let idx = 0;
      for (let r = 0; r < key; r++) {
        rails[r] = text.substring(idx, idx + railLengths[r]).split('');
        idx += railLengths[r];
      }
      let result = '';
      row = 0;
      dir = 1;
      for (let i = 0; i < text.length; i++) {
        result += rails[row].shift();
        row += dir;
        if (row === key - 1 || row === 0) dir = -dir;
      }
      return result;
    },
  },
  columnar: {
    category: 'transposition',
    needsKey: true,
    keyType: 'string',
    encrypt: (text, key) => {
      const cols = key.length;
      const rows = Math.ceil(text.length / cols);
      let grid = Array.from({ length: rows }, () => Array(cols).fill(''));
      let i = 0;
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          grid[r][c] = text[i++] || 'X';
        }
      }
      const order = [...key].map((c, idx) => ({ c, idx })).sort((a, b) => a.c.localeCompare(b.c)).map((a) => a.idx);
      let result = '';
      for (let c of order) {
        for (let r = 0; r < rows; r++) {
          result += grid[r][c];
        }
      }
      return result;
    },
    decrypt: (text, key) => {
      const cols = key.length;
      const rows = Math.ceil(text.length / cols);
      const order = [...key].map((c, idx) => ({ c, idx })).sort((a, b) => a.c.localeCompare(b.c)).map((a) => a.idx);
      let grid = Array.from({ length: rows }, () => Array(cols).fill(''));
      let i = 0;
      for (let c of order) {
        for (let r = 0; r < rows; r++) {
          grid[r][c] = text[i++];
        }
      }
      let result = '';
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          result += grid[r][c];
        }
      }
      return result.replace(/X+$/, '');
    },
  },
  enigma: {
    category: 'mechanical',
    needsKey: true,
    keyType: 'string', // Initial positions e.g. 'AAA'
    encrypt: (text, key) => {
      // Basic 3-rotor Enigma simulation with fixed wirings
      const rotors = [
        'EKMFLGDQVZNTOWYHXUSPAIBRCJ'.split(''), // Rotor I
        'AJDKSIRUXBLHWTMCQGZNPYFVOE'.split(''), // Rotor II
        'BDFHJLCPRTXVZNYEIWGAKMUSQO'.split(''), // Rotor III
      ];
      const reflector = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'.split('');
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
      let positions = key.toUpperCase().split('').map((c) => c.charCodeAt(0) - 65);
      if (positions.length !== 3) return 'Key must be 3 letters (A-Z)';
      text = text.toUpperCase().replace(/[^A-Z]/g, '');
      let result = '';
      for (let char of text) {
        let signal = alphabet.indexOf(char);
        // Step rotors (simple stepping, no notches)
        positions[0] = (positions[0] + 1) % 26;
        if (positions[0] === 0) positions[1] = (positions[1] + 1) % 26;
        if (positions[1] === 0) positions[2] = (positions[2] + 1) % 26;
        // Forward pass
        for (let r = 0; r < 3; r++) {
          signal = (signal + positions[r]) % 26;
          signal = alphabet.indexOf(rotors[r][signal]);
          signal = (signal - positions[r] + 26) % 26;
        }
        // Reflector
        signal = alphabet.indexOf(reflector[alphabet[signal]]);
        // Backward pass
        for (let r = 2; r >= 0; r--) {
          signal = (signal + positions[r]) % 26;
          signal = rotors[r].indexOf(alphabet[signal]);
          signal = (signal - positions[r] + 26) % 26;
        }
        result += alphabet[signal];
      }
      return result;
    },
    decrypt: (text, key) => this.encrypt(text, key), // Symmetric for Enigma
  },
  lorenz: {
    category: 'mechanical',
    needsKey: true,
    keyType: 'string', // Starting positions e.g. '000' (0-4 for each group)
    encrypt: (text, key) => {
      // Simplified Lorenz with fixed wheels (5-bit Baudot, K/S/M wheels)
      // Baudot map (partial for A-Z; extend as needed)
      const baudotMap = {
        'A': [1, 1, 0, 0, 0],
        'B': [1, 0, 0, 1, 1],
        'C': [0, 1, 1, 1, 0],
        'D': [1, 0, 0, 1, 0],
        'E': [1, 0, 0, 0, 0],
        'F': [1, 0, 1, 1, 0],
        'G': [0, 0, 1, 1, 1],
        'H': [0, 0, 1, 0, 1],
        'I': [0, 1, 1, 0, 0],
        'J': [1, 1, 0, 1, 0],
        'K': [1, 1, 1, 1, 0],
        'L': [0, 1, 0, 0, 1],
        'M': [0, 0, 1, 1, 0],
        'N': [0, 0, 1, 0, 0],
        'O': [0, 0, 0, 1, 1],
        'P': [0, 1, 1, 0, 1],
        'Q': [1, 1, 1, 0, 1],
        'R': [0, 1, 0, 1, 0],
        'S': [1, 0, 1, 0, 0],
        'T': [0, 0, 0, 0, 1],
        'U': [0, 1, 1, 1, 1],
        'V': [0, 1, 1, 1, 1],
        'W': [1, 1, 0, 0, 1],
        'X': [1, 0, 1, 1, 1],
        'Y': [1, 0, 1, 0, 1],
        'Z': [1, 0, 0, 0, 1],
      };
      const reverseBaudot = {};
      for (let char in baudotMap) reverseBaudot[baudotMap[char].join('')] = char;
      // Fixed wheels
      let K_wheels = [
        [1, 1, 0, 1, 0],
        [0, 1, 0, 0, 1],
        [1, 0, 0, 1, 0],
        [1, 1, 1, 0, 1],
        [1, 0, 0, 0, 1],
      ];
      let S_wheels = [
        [1, 0, 1, 0, 1],
        [0, 1, 1, 0, 0],
        [1, 0, 1, 1, 0],
        [0, 1, 0, 1, 1],
        [1, 1, 0, 1, 0],
      ];
      let M_wheel = [0, 0, 1, 0, 1];
      // Parse key positions (0-4)
      let [kPos, sPos, mPos] = key.split('').map(Number);
      const rotate = (arr, n = 1) => arr.slice(n).concat(arr.slice(0, n));
      let currentK = K_wheels.map((w) => rotate(w, kPos));
      let currentS = S_wheels.map((w) => rotate(w, sPos));
      let currentM = rotate(M_wheel, mPos);
      text = text.toUpperCase();
      let result = '';
      for (let char of text) {
        if (!baudotMap[char]) continue;
        let baudot = baudotMap[char];
        // XOR with K wheels (current position 0)
        let intermediate = baudot.map((b, i) => b ^ currentK[i][0]);
        // XOR with S wheels
        let encrypted = intermediate.map((b, i) => b ^ currentS[i][0]);
        result += reverseBaudot[encrypted.join('')] || '?';
        // Rotate K always
        currentK = currentK.map(rotate);
        // Rotate M always
        currentM = rotate(currentM);
        // Rotate S if M[0] == 1
        if (currentM[0] === 1) currentS = currentS.map(rotate);
      }
      return result;
    },
    decrypt: (text, key) => this.encrypt(text, key), // Symmetric
  },
  xor: {
    category: 'modern',
    needsKey: true,
    keyType: 'string',
    encrypt: (text, key) => {
      let result = '';
      for (let i = 0; i < text.length; i++) {
        result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
      }
      return btoa(result);
    },
    decrypt: (text, key) => {
      try {
        text = atob(text);
      } catch (e) {
        return 'Invalid base64 input';
      }
      let result = '';
      for (let i = 0; i < text.length; i++) {
        result += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
      }
      return result;
    },
  },
  aes: {
    category: 'modern',
    needsKey: true,
    keyType: 'string', // Password
    encrypt: async (text, password) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const salt = window.crypto.getRandomValues(new Uint8Array(8));
      const key = await deriveKey(password, salt);
      const iv = window.crypto.getRandomValues(new Uint8Array(16));
      const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, data);
      const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
      combined.set(salt, 0);
      combined.set(iv, salt.length);
      combined.set(new Uint8Array(encrypted), salt.length + iv.length);
      return btoa(String.fromCharCode(...combined));
    },
    decrypt: async (text, password) => {
      const decoder = new TextDecoder();
      let combined;
      try {
        combined = new Uint8Array([...atob(text)].map((c) => c.charCodeAt(0)));
      } catch (e) {
        return 'Invalid base64 input';
      }
      const salt = combined.slice(0, 8);
      const iv = combined.slice(8, 24);
      const encrypted = combined.slice(24);
      const key = await deriveKey(password, salt);
      const decrypted = await window.crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, encrypted);
      return decoder.decode(decrypted);
    },
  },
  rsa: {
    category: 'modern',
    needsKey: false, // Handled specially with generate
    keyType: 'special',
    generateKeys: async () => {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );
      const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
      const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      return {
        public: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
        private: btoa(String.fromCharCode(...new Uint8Array(privateKey))),
      };
    },
    encrypt: async (text, publicBase64) => {
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      let publicBuffer;
      try {
        publicBuffer = new Uint8Array([...atob(publicBase64)].map((c) => c.charCodeAt(0)));
      } catch (e) {
        return 'Invalid public key';
      }
      const publicKey = await window.crypto.subtle.importKey(
        'spki',
        publicBuffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      );
      const encrypted = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
      return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    },
    decrypt: async (text, privateBase64) => {
      const decoder = new TextDecoder();
      let data;
      try {
        data = new Uint8Array([...atob(text)].map((c) => c.charCodeAt(0)));
      } catch (e) {
        return 'Invalid encrypted text';
      }
      let privateBuffer;
      try {
        privateBuffer = new Uint8Array([...atob(privateBase64)].map((c) => c.charCodeAt(0)));
      } catch (e) {
        return 'Invalid private key';
      }
      const privateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        privateBuffer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
      );
      const decrypted = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, data);
      return decoder.decode(decrypted);
    },
  },
};

// Helper for AES key derivation
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return await window.crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// UI Elements
const inputText = document.getElementById('input-text');
const outputText = document.getElementById('output-text');
const cipherSelect = document.getElementById('cipher-select');
const keyInputContainer = document.getElementById('key-input-container');
const keyInput = document.getElementById('key-input');
const encryptBtn = document.getElementById('encrypt-btn');
const decryptBtn = document.getElementById('decrypt-btn');
const copyBtn = document.getElementById('copy-btn');
const clearBtn = document.getElementById('clear-btn');
const modeToggle = document.getElementById('mode-toggle');
const historyList = document.getElementById('history-list');

// Populate cipher select
Object.keys(ciphers).forEach((key) => {
  const option = document.createElement('option');
  option.value = key;
  option.textContent = key.replace(/-/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
  cipherSelect.appendChild(option);
});

// Sidebar click to select cipher
document.querySelectorAll('.sidebar li[data-cipher]').forEach((li) => {
  li.addEventListener('click', () => {
    cipherSelect.value = li.dataset.cipher;
    cipherSelect.dispatchEvent(new Event('change'));
  });
});

let history = [];
let rsaPublicTa, rsaPrivateTa;

// Handle cipher change for dynamic key input
function handleCipherChange() {
  const cipher = cipherSelect.value;
  keyInputContainer.innerHTML = ''; // Clear previous
  if (ciphers[cipher] && ciphers[cipher].needsKey) {
    keyInputContainer.style.display = 'block';
    if (cipher === 'rsa') {
      // Special for RSA: generate button and textareas
      const generateBtn = document.createElement('button');
      generateBtn.textContent = 'Generate Keys';
      generateBtn.addEventListener('click', async () => {
        const keys = await ciphers.rsa.generateKeys();
        rsaPublicTa.value = keys.public;
        rsaPrivateTa.value = keys.private;
      });
      rsaPublicTa = document.createElement('textarea');
      rsaPublicTa.placeholder = 'Public Key (base64)';
      rsaPrivateTa = document.createElement('textarea');
      rsaPrivateTa.placeholder = 'Private Key (base64)';
      keyInputContainer.appendChild(generateBtn);
      keyInputContainer.appendChild(rsaPublicTa);
      keyInputContainer.appendChild(rsaPrivateTa);
    } else {
      // Standard input
      const input = document.createElement('input');
      input.id = 'key-input';
      input.type = ciphers[cipher].keyType === 'number' ? 'number' : 'text';
      input.placeholder = 'Enter key...';
      keyInputContainer.appendChild(input);
    }
  } else {
    keyInputContainer.style.display = 'none';
  }
}

cipherSelect.addEventListener('change', handleCipherChange);

// Process encryption/decryption
async function process(mode) {
  const cipher = cipherSelect.value;
  if (!cipher || !ciphers[cipher]) return;
  const text = inputText.value;
  let key;
  if (cipher === 'rsa') {
    key = mode === 'encrypt' ? rsaPublicTa?.value : rsaPrivateTa?.value;
    if (!key) return outputText.value = 'Provide key';
  } else {
    key = document.getElementById('key-input')?.value || '';
  }
  outputText.classList.add('shimmer');
  try {
    const func = mode === 'encrypt' ? ciphers[cipher].encrypt : ciphers[cipher].decrypt;
    const result = await func(text, key);
    outputText.value = typeof result === 'string' ? result : 'Error: Invalid result';
    addToHistory(cipher, mode, text, outputText.value);
  } catch (e) {
    outputText.value = `Error: ${e.message}`;
  } finally {
    outputText.classList.remove('shimmer');
    outputText.style.animation = 'fadeIn 0.5s';
  }
}

encryptBtn.addEventListener('click', () => process('encrypt'));
decryptBtn.addEventListener('click', () => process('decrypt'));

// Copy with animation
copyBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(outputText.value);
  copyBtn.classList.add('success');
  setTimeout(() => copyBtn.classList.remove('success'), 1000);
});

// Clear with shake
clearBtn.addEventListener('click', () => {
  inputText.value = '';
  outputText.value = '';
});

// Mode toggle with smooth transition
modeToggle.addEventListener('click', () => {
  document.body.classList.toggle('dark');
});

// Add to history (last 5)
function addToHistory(cipher, mode, input, output) {
  history.push({ cipher, mode, input, output });
  if (history.length > 5) history.shift();
  historyList.innerHTML = '';
  history.forEach((entry, index) => {
    const card = document.createElement('div');
    card.className = 'history-card';
    card.style.animationDelay = `${index * 0.1}s`;
    card.innerHTML = `
      <strong>${entry.cipher.toUpperCase()} - ${mode.toUpperCase()}</strong><br>
      Input: ${entry.input.slice(0, 30)}...<br>
      Output: ${entry.output.slice(0, 30)}...
    `;
    historyList.appendChild(card);
  });
}