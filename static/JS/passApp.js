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
  const uploadTile = document.querySelector('.vaultUploadTile');
  const vaultLinksContainer = document.getElementById('vaultLinks');

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

    // Insert before the upload tile so it stays last
    vaultLinksContainer.insertBefore(vaultNode, uploadTile);

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
    await fancyAlert("Failed to load vault");
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
  let passToUnlock = parent.querySelector('.vaultPasswordInput').value || '';

  // TO-DO: Separate button for biometrics
  if (passToUnlock === '' && await isBiometricAvailable()) {
    try {
      let kdbxPassword = await unlockVaultWithBiometric(this.vaultName);
      if (kdbxPassword) {
        passToUnlock = kdbxPassword;
      } else {
        await fancyAlert("Biometric authentication succeeded but failed to retrieve password");
        return;
      }
    } catch (error) {
      console.error("Failed to unlock with biometric: ", error);
      await fancyAlert("Failed to unlock with biometric. See console for details.");
      return;
    }
  }

  let vaultToLoad = userVaults[String(this.vaultName)];

  let passCardTemplate = document.querySelector('.entry-content-template');
  let entryList = document.getElementById('entryList');
  let entriesSection = document.getElementById('entriesSection');

  // Use kdbxweb to decrypt
  const creds = new Credentials(ProtectedValue.fromString(passToUnlock));

  try {
    const db = await Kdbx.load(vaultToLoad, creds);

    if (await isBiometricAvailable() && !(await isBiometricSavedForVault(this.vaultName))) {
      biometricsSavePassPrompt(this.vaultName, passToUnlock);
    }

    /* TO-DO: GLOBALLY THROUGHOUT PROJECT */
    /*
      - Highlight the currently unlocked vault
      - Add global control that controls auto-save or not,
        make sure this setting is saved in local storage
      - Make row sections take as little width as possible. (As many
        as you can get width-wise on screen)
      - PERHAPS, add global control to auto show password on expand (again
        savable)
    */
    /* END TO-DO: GLOBALLY THROUGHOUT PROJECT */

    // Show the controls now that entries are loading
    document.getElementById('entryControls').style.display = 'block';

    for (const entry of db.groups[0].entries) {
      const title = entry.fields.get('Title') || '';
      const username = entry.fields.get('UserName') || '';
      const passwordField = entry.fields.get('Password') || '';
      const urlField = entry.fields.get('Url') || '';
      const notesField = entry.fields.get('Notes') || '';
      const tagElems = entry.tags || [];
      const lastModified = entry.times?.lastModTime || null;

      let password = '';
      if (passwordField && typeof passwordField.getText === 'function') {
        password = await passwordField.getText();
      }

      // The UI element
      let clonedCard = passCardTemplate.cloneNode(true);
      clonedCard.classList.remove('entry-content-template');

      // Populate bubble
      clonedCard.querySelector('.bubble-title').textContent = title || '(Untitled)';

      const bubbleTagsEl = clonedCard.querySelector('.bubble-tags');
      if (tagElems.length > 0) {
        tagElems.forEach(tag => {
          let tagSpan = document.createElement('span');
          tagSpan.classList.add('tag');
          tagSpan.textContent = tag;
          bubbleTagsEl.appendChild(tagSpan);
        });
      }

      const modifiedStr = lastModified ? new Date(lastModified).toLocaleDateString() : '';
      clonedCard.querySelector('.bubble-modified').textContent = modifiedStr;

      // Store data attributes for sort/filter
      clonedCard.dataset.title = (title || '').toLowerCase();
      clonedCard.dataset.tags = tagElems.map(t => t.toLowerCase()).join(',');
      clonedCard.dataset.modified = lastModified ? new Date(lastModified).getTime() : '0';

      // Populate expanded fields
      clonedCard.querySelector('.entry-title').value = title;
      clonedCard.querySelector('.entry-username').value = username;
      clonedCard.querySelector('.entry-password').value = password;
      clonedCard.querySelector('.entry-url').value = urlField;
      clonedCard.querySelector('.entry-notes').value = notesField;
      tagElems.reverse().forEach((tag) => {
        let tagElem = document.createElement('span');
        tagElem.classList.add('tag')
        tagElem.textContent = tag;
        clonedCard.querySelector('.tags-container').prepend(tagElem);
      });

      // Click bubble to toggle expand/collapse
      clonedCard.querySelector('.entry-bubble').addEventListener('click', () => {
        clonedCard.classList.toggle('entry-card--expanded');
      });

      // UI Element event listener for show/hide of password
      let pwdPassRehideTimer;
      clonedCard.querySelector('.entry-btn--toggle-password').addEventListener('click', (e) => {
        let pwdInput = e.target.closest('.entry-card').querySelector('.entry-password');
        if (pwdPassRehideTimer) {
          clearTimeout(pwdPassRehideTimer);
        }
        if (pwdInput.type === 'password') {
          pwdInput.type = 'text';
          e.target.textContent = '👀';
          pwdPassRehideTimer = setTimeout(() => {
            clonedCard.querySelector('.entry-btn--toggle-password').dispatchEvent(new Event('click'));
          }, 55000);
        } else {
          pwdInput.type = 'password';
          e.target.textContent = '👁️';
        }
      });

      entryList.appendChild(clonedCard);
    }
  } catch (err) {
    console.error('Failed to unlock vault: ', err);
    await fancyAlert('Failed to unlock vault');
  }
};

async function vaultDeleteListener(e) {
  e.preventDefault();

  // TO-DO: Come up with custom modal for confirmation instead of browser default
  if (!await fancyConfirm(`Are you sure you want to delete the vault: ${this.vaultName}? This action cannot be undone.`)) {
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

async function biometricsSavePassPrompt(vaultName, password) {
  if (await isBiometricAvailable() === false) {
    return;
  }
  if (!await fancyConfirm("Would you like to save a biometric credential for easier vault access in the future?")) {
    return;
  }

  try {
    await enableBiometricForVault(vaultName, password);
  } catch (error) {
    console.error("Failed to enable biometric for vault: ", error);
    await fancyAlert("Failed to enable biometric for vault. See console for details.");
  }
}

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

// Track current sort state: { field: 'name'|'modified', dir: 'asc'|'desc' } or null
let currentSort = null;

document.querySelectorAll('.entry-sort-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const field = btn.dataset.sort;

    if (currentSort && currentSort.field === field) {
      // Toggle direction
      currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
    } else {
      currentSort = { field, dir: 'asc' };
    }

    // Update arrow indicators
    document.querySelectorAll('.entry-sort-btn').forEach(b => {
      b.querySelector('.sort-arrow').textContent = '';
      b.classList.remove('sort-active');
    });
    btn.querySelector('.sort-arrow').textContent = currentSort.dir === 'asc' ? '▲' : '▼';
    btn.classList.add('sort-active');

    applySortAndFilter();
  });
});

(document.getElementById('entryFilterInput') || fbNode).addEventListener('input', () => {
  applySortAndFilter();
});

function applySortAndFilter() {
  const entryList = document.getElementById('entryList');
  if (!entryList) return;

  const filterText = (document.getElementById('entryFilterInput')?.value || '').toLowerCase().trim();
  let cards = Array.from(entryList.querySelectorAll('.entry-card'));

  // Filter based on title or tags
  cards.forEach(card => {
    const title = card.dataset.title || '';
    const tags = card.dataset.tags || '';
    const matches = !filterText || title.includes(filterText) || tags.includes(filterText);
    card.style.display = matches ? '' : 'none';
  });

  // Sort (only visible cards reorder, hidden stay in DOM)
  if (currentSort) {
    cards.sort((a, b) => {
      let valA, valB;
      if (currentSort.field === 'name') {
        valA = a.dataset.title || '';
        valB = b.dataset.title || '';
        return currentSort.dir === 'asc'
          ? valA.localeCompare(valB)
          : valB.localeCompare(valA);
      } else {
        valA = parseInt(a.dataset.modified) || 0;
        valB = parseInt(b.dataset.modified) || 0;
        return currentSort.dir === 'asc' ? valA - valB : valB - valA;
      }
    });

    // Reinsert in sorted order
    cards.forEach(card => entryList.appendChild(card));
  }
}