const { Credentials, ProtectedValue, Kdbx } = kdbxweb;
const csrf_token = document.getElementById('token').value || '';
const fbNode = document.createElement("div") // More terse for conditional event listener attachment

function generateSalt(length = 16) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

// For authenticated users, keep track of their loaded vaults
let userVaultsNames = {};
let userVaults = {};

async function listVaults() {
    await fetch('/list-vaults', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'X-CSRFToken': csrf_token
        },
    })
    .then(res => res.json())
    .then(data => {
      userVaultsNames = data.vaults || {};
      buildVaultListLinks(userVaultsNames);
    })
    .catch(err => console.error(err));
}
listVaults();

async function buildVaultListLinks(vaults) {
  const template = document.querySelector('.vaultItemTemplate');
  vaults.forEach(vault => {
    // Clone the entire node
    let vaultNode = template.cloneNode(true);

    // Remove hidden styles / classes
    vaultNode.style.display = '';
    vaultNode.classList.remove('vaultItemTemplate');

    // Update the vault name inside the clone
    let nameEl = vaultNode.querySelector('.vaultName');
    if (nameEl) {
      nameEl.innerHTML = `<strong>Vault:</strong> ${vault}`;
    }

    // Append to the list
    document.getElementById('vaultLinks').appendChild(vaultNode);

    // And add event listener to unlock the vault
    let unlockBtnElem = vaultNode.querySelector('.unlockVault');
    unlockBtnElem.addEventListener('click', vaultUnlockListener.bind({vaultName: vault}));

    // And add event listener to delete the vault
    let deleteBtnElem = vaultNode.querySelector('.deleteVault');
    deleteBtnElem.addEventListener('click', vaultDeleteListener.bind({vaultName: vault}));

    // And actually download the vault
    downloadVault(vault);
  });
}

async function downloadVault(vaultName) {
  const formData = new FormData();
  formData.append('vault_name', vaultName);
  // Fetch encrypted vault contents from Flask and save to global
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
  userVaults[String(vaultName)] = arrayBuffer;
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

async function vaultUnlockListener(e) {

  // The button that was clicked
  const btn = e.target;
  const parent = btn.closest('.vaultPasswordFormDiv');
  // Find the password input inside it
  const passToUnlock = parent.querySelector('.vaultPasswordInput').value || '';

  let vaultToLoad = userVaults[String(this.vaultName)];

  // Use kdbxweb to decrypt
  const creds = new Credentials(ProtectedValue.fromString(passToUnlock));
  const db = await Kdbx.load(vaultToLoad, creds);

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
};

async function vaultDeleteListener(e) {
  e.preventDefault();

  // TO-DO: Come up with custom modal for confirmation instead of browser default
  if (!confirm(`Are you sure you want to delete the vault: ${this.vaultName}? This action cannot be undone.`)) {
    return;
  }

  const formData = new FormData();
  formData.append('csrf_token', csrf_token);
  formData.append('vault_name', this.vaultName);

  // For message display logic
  let inPageWarningMsg = '';

  try {
      const response = await fetch('/delete-vault', {
          method: 'POST',
          body: formData,
          credentials: 'include',
          headers: {
              'X-CSRFToken': csrf_token
          }
      });

      const result = await response.json();

      if (response.ok) {
          window.location.reload();
      } else {
          inPageWarningMsg = `Delete failed: ${result.msg}`;
      }
  } catch (error) {
      inPageWarningMsg = 'Delete failed due to network error';
  }

  // Show the warning with fade-in (if needed)
  showInlineWarning(inPageWarningMsg);
};

// Upload Vault KDBX File form event listener
(document.getElementById('uploadForm') || fbNode).addEventListener('submit', async (event) => {
    event.preventDefault();

    const formData = new FormData(event.target);
    formData.append('csrf_token', csrf_token);

    // For message display logic
    let inPageWarningMsg = '';

    try {
        const response = await fetch('/upload-vault', {
            method: 'POST',
            body: formData,
            credentials: 'include',
            headers: {
                'X-CSRFToken': csrf_token
            }
        });

        const result = await response.json();

        if (response.ok) {
            window.location.reload();
        } else {
            inPageWarningMsg = `Upload failed: ${result.msg}`;
        }
    } catch (error) {
        inPageWarningMsg = 'Upload failed due to network error';
    }

    // Show the warning with fade-in (if needed)
    showInlineWarning(inPageWarningMsg);
});

function showInlineWarning(inPageWarningMsg) {
  if (!inPageWarningMsg) return;

  let warningClassElem = document.getElementsByClassName('fade-warning')[0];
  warningClassElem.textContent = inPageWarningMsg;
  warningClassElem.scrollIntoView({ behavior: 'smooth' });
  warningClassElem.classList.remove('fade-warning');
  void warningClassElem.offsetWidth; // Trigger reflow (needed for css effect)
  warningClassElem.classList.add('fade-warning');
}