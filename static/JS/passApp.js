const { Credentials, ProtectedValue, Kdbx } = kdbxweb;

function generateSalt(length = 16) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

async function generatePasswordHash(plainTextPass, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(plainTextPass), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateUserCreds() {
  let userSalt = generateSalt();
  let userPass = 'simplePass'; // Grabbed from form element
  let userHashPass = await generatePasswordHash(userPass, userSalt);
  let hashPassToPostB64 = btoa(userHashPass);
  console.log('Generated salt: ', userSalt);
  console.log('User Provided Plaintext Pass: ', userPass);
  console.log('User Hashed Pass: ', userHashPass);
  console.log('User Hashed Pass To Post: ', hashPassToPostB64);
}
generateUserCreds();

document.getElementById('loadFileLocal').addEventListener('click', async function (e) {
  e.preventDefault();

  const formData = new FormData(document.getElementById('loadDb'));

  // Re-use the app auth form, to replace later. Only used after file download, not sent to server in this manner.
  const password = document.getElementById('keepass_pass').value;

  // Fetch encrypted vault contents from Flask
  const res = await fetch('/download-vault', {
    method: 'POST',
    body: formData
  });

  if (!res.ok) {
    alert("Failed to load vault");
    return;
  }

  const arrayBuffer = await res.arrayBuffer();

  // Use kdbxweb to decrypt
  const creds = new Credentials(ProtectedValue.fromString(password));
  const db = await Kdbx.load(arrayBuffer, creds);

  console.log("Vault loaded!", db);
  for (const entry of db.groups[0].entries) {
    const title = entry.fields.get('Title');
    const username = entry.fields.get('UserName');
    const passwordField = entry.fields.get('Password');

    let password = '';
    if (passwordField && typeof passwordField.getText === 'function') {
      password = await passwordField.getText();
    }

    console.log(title, username, password);
  }
});