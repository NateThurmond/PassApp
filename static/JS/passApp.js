const { Credentials, ProtectedValue, Kdbx } = kdbxweb;
const csrf_token = document.getElementById('token').value || '';

function generateSalt(length = 16) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

document.getElementById('signUpForm').addEventListener('submit', async (event) => {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);

    // Hold onto password until next step - do not post
    const userName = (formData.get('up_user_name') || '').trim();
    const userEmail = (formData.get('up_user_email') || '').trim();
    const userPass = (formData.get('up_user_pass') || '').trim();
    formData.delete['up_user_pass'];

    await fetch('/signUpCheckUser', {
        method: form.method,
        body: formData,
        credentials: 'include',
        headers: {
          'X-CSRFToken': csrf_token
        },
    })
    .then(res => res.json())
    .then(data => {
      console.log(data.msg);
      if (data.msg === "Username/email available") {
        processSignUp(userName, userEmail, userPass, formData);
      }
    })
    .catch(err => console.error(err));
});

async function processSignUp(userName, userEmail, userPass, formData) {
  const userSalt = generateSalt();
  const { saltHex, verifierHex } =
    await computeSrpVerifier(userName, userPass, userSalt);

  // Additional form data elements to send in signup payload
  const signUpPayload = {
    // userName,
    // userEmail,
    salt: saltHex,
    verifier: verifierHex,
    group: "RFC5054-2048",
    hash: "SHA-256",
    g: 2
  };

  for (const [key, value] of Object.entries(signUpPayload)) {
    formData.append(key, value);
  }

  await fetch('/signUp', {
      method: 'POST',
      body: formData,
      credentials: 'include',
      headers: {
        'X-CSRFToken': csrf_token
      },
  })
  .then(res => res.json())
  .then(data => {
    console.log('Signup result: ', data);
  })
  .catch(err => console.error(err));
}

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