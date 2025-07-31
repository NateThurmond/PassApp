const { Credentials, ProtectedValue, Kdbx } = kdbxweb;

document.getElementById('loadFileLocal').addEventListener('click', async function (e) {
  e.preventDefault();

  const formData = new FormData(document.getElementById('passAppLogin'));

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