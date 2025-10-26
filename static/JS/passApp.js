const { Credentials, ProtectedValue, Kdbx } = kdbxweb;
const csrf_token = document.getElementById('token').value || '';
const fbNode = document.createElement("div") // More terse for conditional event listener attachment

function generateSalt(length = 16) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

(document.getElementById('signUpForm') || fbNode).addEventListener('submit', async (event) => {
    event.preventDefault();

    // Re-use some of the inputs from the login form for cleaner UI
    if (!document.getElementById('loginForm').reportValidity()) {
      return;
    }

    const passMatch = (a = document.getElementById('land_user_pass')?.value,
      b = document.getElementById('verify_user_pass')?.value) => a && b && a === b;

    if (!passMatch()) {
      document.getElementById('verify_user_pass').setCustomValidity("Passwords do not match");
      document.getElementById('signUpForm').reportValidity();
      return;
    }

    const form = event.target;
    const formData = new FormData(form);

    // Hold onto password until next step - do not post
    const userName = document.getElementById('land_user_name')?.value.trim().toLowerCase();
    formData.append('land_user_name', userName);
    const userPass = document.getElementById('land_user_pass')?.value.trim();
    const userEmail = (formData.get('land_user_email') || '').trim();
    formData.delete['land_user_pass'];

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
    if (data?.msg === 'User successfully added') {
      document.getElementById('loginForm').requestSubmit();
    }
  })
  .catch(err => console.error(err));
}

(document.getElementById('loginForm') || fbNode).addEventListener('submit', async (event) => {
  event.preventDefault();

  const form = event.target;
  const formData = new FormData(form);

  const userName = (formData.get('land_user_name') || '').trim().toLowerCase();
  const userPass = (formData.get('land_user_pass') || '').trim();
  formData.delete['land_user_pass']; // Never send to server

  let clientEphemeralA = genClientEphemeral();
  formData.append('clientEphemeralA', clientEphemeralA.Ahex);

  await fetch('/login/srp/start', {
      method: form.method,
      body: formData,
      credentials: 'include',
      headers: {
        'X-CSRFToken': csrf_token
      },
  })
  .then(res => res.json())
  .then(async data => {
    // Nominally ... {"msg": message, "B": B_hex, "Salt": foundUserSalt, "config_version": config_version}
    if (data.msg === "All Okay") {

      const A_big = hexToBigInt(clientEphemeralA.Ahex);
      const B_big = hexToBigInt(data.B);
      const saltBytes = hexToBytes(data.Salt);

      const k = BigInt("0x" + bytesToHex(await sha256Bytes(bigIntToBytes(N), bigIntToBytes(g))));
      const u = BigInt("0x" + bytesToHex(await sha256Bytes(bigIntToBytes(A_big), bigIntToBytes(B_big))));
      const x = BigInt("0x" + bytesToHex(await sha256(concatBytes(saltBytes, await sha256(utf8(`${userName}:${userPass}`))))));

      const S = modPow(((B_big - (k * modPow(g, x, N)) % N) + N) % N, (clientEphemeralA.a + u * x), N);
      const K_bytes = await sha256Bytes(bigIntToBytes(S));

      const M1_hex = await computeM1(userName, saltBytes, A_big, B_big, K_bytes, N, g);

      await verifyLogin(userName, M1_hex, data.accessionId || '');
    }
  })
  .catch(err => console.error(err));
});

async function verifyLogin(userName, M1_hex, accessionId) {
  let formData = new FormData();
  formData.append('land_user_name', userName);
  formData.append('client_proof_m1', M1_hex);
  formData.append('accessionId', accessionId);
  fetch('/login/srp/verify', {
      method: 'POST',
      body: formData,
      credentials: 'include',
      headers: {
        'X-CSRFToken': csrf_token
      },
  })
  .then(res => res.json())
  .then(async data => {
    // The proof validation login result
    console.log(data);
    // Nominally sets session cookie (or error handling TO-DO)
    if (data?.msg === 'Login successful!') {
      window.location.reload();
    }
  })
  .catch(err => console.error(err));
}

(document.getElementById('logout') || fbNode).addEventListener('click', async (e) => {
  e.preventDefault();

  await fetch('/logout', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'X-CSRFToken': csrf_token
      },
  })
  .then(res => res.json())
  .then(data => {
    if (data.msg === "Logged out") {
      window.location.reload();
    }
  })
  .catch(err => console.error(err));
});

(document.getElementById('loadFileLocal') || fbNode).addEventListener('click', async (e) => {
  e.preventDefault();

  const formData = new FormData(document.getElementById('loadDb'));

  // Re-use the app auth form, to replace later. Only used after file download, not sent to server in this manner.
  const password = document.getElementById('keepass_pass').value;

  // Fetch encrypted vault contents from Flask
  const res = await fetch('/download-vault', {
    method: 'POST',
    body: formData,
    credentials: 'include',
    headers: {
      'X-CSRFToken': csrf_token
    },
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