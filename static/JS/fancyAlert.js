// JavaScript wrapper functions to make the alerts/prompts/confirms look a bit better
function fancyAlert(message) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'custom-modal-overlay';
    overlay.innerHTML = `
      <div class="custom-modal">
        <p>${message}</p>
        <button onclick="this.closest('.custom-modal-overlay').remove()">OK</button>
      </div>
    `;

    overlay.querySelector('button').addEventListener('click', () => {
      overlay.remove();
      resolve();
    });

    document.body.appendChild(overlay);
  });
}

function fancyConfirm(message) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'custom-modal-overlay';
    overlay.innerHTML = `
      <div class="custom-modal">
        <p>${message}</p>
        <button class="confirm-btn">OK</button>
        <button class="cancel-btn" style="background: #6c757d;">Cancel</button>
      </div>
    `;

    const handleResponse = (result) => {
      overlay.remove();
      resolve(result);
    };

    overlay.querySelector('.confirm-btn').addEventListener('click', () => handleResponse(true));
    overlay.querySelector('.cancel-btn').addEventListener('click', () => handleResponse(false));

    document.body.appendChild(overlay);
  });
}

function fancyPrompt(message, defaultValue = '') {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'custom-modal-overlay';
    overlay.innerHTML = `
      <div class="custom-modal">
        <p>${message}</p>
        <input type="text" value="${defaultValue}" />
        <button class="confirm-btn">OK</button>
        <button class="cancel-btn" style="background: #6c757d;">Cancel</button>
      </div>
    `;

    const input = overlay.querySelector('input');
    const handleResponse = (confirmed) => {
      const value = confirmed ? input.value : null;
      overlay.remove();
      resolve(value);
    };

    overlay.querySelector('.confirm-btn').addEventListener('click', () => handleResponse(true));
    overlay.querySelector('.cancel-btn').addEventListener('click', () => handleResponse(false));

    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') handleResponse(true);
    });

    document.body.appendChild(overlay);
    input.focus();
  });
}