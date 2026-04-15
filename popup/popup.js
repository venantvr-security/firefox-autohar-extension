// AutoHAR Popup Script
// Affiche l'état de la capture et contrôle le démarrage/arrêt

const UI = {
  statusValue: document.getElementById('statusValue'),
  requestCount: document.getElementById('requestCount'),
  totalSize: document.getElementById('totalSize'),
  fileCount: document.getElementById('fileCount'),
  progressFill: document.getElementById('progressFill'),
  progressText: document.getElementById('progressText'),
  startBtn: document.getElementById('startBtn'),
  stopBtn: document.getElementById('stopBtn'),
  settingsBtn: document.getElementById('settingsBtn'),
  savedFiles: document.getElementById('savedFiles'),
  filesList: document.getElementById('filesList')
};

let currentState = {
  isRecording: false,
  requestCount: 0,
  totalSizeMB: 0,
  savedCount: 0,
  maxSizeMB: 5,
  lastSavedFile: null,
  panelConnected: false
};

let pollingInterval = null;

// Initialiser
document.addEventListener('DOMContentLoaded', async () => {
  // Charger l'état initial
  await updateUIFromStorage();
  await checkPanelStatus();

  // Écouter les changements de storage (principal mécanisme de sync)
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && (changes.captureState || changes.settings)) {
      updateUIFromStorage();
    }
  });

  // Boutons
  UI.startBtn.addEventListener('click', startRecording);
  UI.stopBtn.addEventListener('click', stopRecording);
  UI.settingsBtn.addEventListener('click', () => {
    browser.runtime.openOptionsPage();
  });

  // Polling de secours (réduit à 2s au lieu de 500ms)
  pollingInterval = setInterval(() => {
    updateUIFromStorage();
    checkPanelStatus();
  }, 2000);
});

async function checkPanelStatus() {
  try {
    const response = await browser.runtime.sendMessage({ action: 'getPanelStatus' });
    currentState.panelConnected = response?.connected || false;
    updateConnectionIndicator();
  } catch (e) {
    currentState.panelConnected = false;
    updateConnectionIndicator();
  }
}

function updateConnectionIndicator() {
  // Mettre à jour l'indicateur visuel de connexion DevTools
  const existingIndicator = document.getElementById('devtoolsIndicator');

  if (!currentState.panelConnected) {
    if (!existingIndicator) {
      const indicator = document.createElement('div');
      indicator.id = 'devtoolsIndicator';
      indicator.className = 'devtools-warning';
      indicator.innerHTML = `
        <strong>⚠ DevTools fermés</strong><br>
        <span>Appuyez sur <kbd>F12</kbd> puis ouvrez l'onglet AutoHAR</span>
      `;
      // Insérer avant les boutons
      const buttonGroup = document.querySelector('.button-group');
      buttonGroup.parentNode.insertBefore(indicator, buttonGroup);
    }
  } else {
    if (existingIndicator) {
      existingIndicator.remove();
    }
  }
}

async function updateUIFromStorage() {
  try {
    const data = await browser.storage.local.get(['captureState', 'settings']);
    const state = data.captureState || {};
    const settings = data.settings || {};

    currentState = {
      ...currentState,
      isRecording: state.isRecording || false,
      requestCount: state.requestCount || 0,
      totalSizeMB: state.totalSizeMB || 0,
      savedCount: state.savedCount || 0,
      lastSavedFile: state.lastSavedFile || null,
      maxSizeMB: settings.maxSizeMB || 5
    };

    updateUI();
  } catch (e) {
    console.error('Erreur chargement state:', e);
  }
}

function updateUI() {
  // Status
  let status = 'Inactif';
  if (!currentState.panelConnected) {
    status = 'DevTools fermés';
  } else if (currentState.isRecording) {
    status = 'Enregistrement...';
  }

  UI.statusValue.textContent = status;
  UI.statusValue.classList.toggle('recording', currentState.isRecording);
  UI.statusValue.classList.toggle('disconnected', !currentState.panelConnected);

  // Stats
  UI.requestCount.textContent = currentState.requestCount;
  UI.totalSize.textContent = currentState.totalSizeMB.toFixed(2) + ' MB';
  UI.fileCount.textContent = currentState.savedCount;

  // Progress bar
  const percent = Math.min((currentState.totalSizeMB / currentState.maxSizeMB) * 100, 100);
  UI.progressFill.style.width = percent + '%';
  UI.progressText.textContent = `${currentState.totalSizeMB.toFixed(2)} / ${currentState.maxSizeMB} MB`;

  // Progress color
  UI.progressFill.classList.remove('warning', 'danger');
  if (percent >= 80) {
    UI.progressFill.classList.add('danger');
  } else if (percent >= 50) {
    UI.progressFill.classList.add('warning');
  }

  // Buttons state
  UI.startBtn.disabled = currentState.isRecording || !currentState.panelConnected;
  UI.stopBtn.disabled = !currentState.isRecording || !currentState.panelConnected;

  // Saved files list
  if (currentState.lastSavedFile) {
    UI.savedFiles.style.display = 'block';
    const filename = currentState.lastSavedFile.filename.split('/').pop();
    UI.filesList.innerHTML = `
      <div class="saved-file-item">
        <span class="saved-file-name">${filename}</span>
        <span class="saved-file-size">${currentState.lastSavedFile.size?.toFixed(2) || '?'} MB</span>
      </div>
    `;
  } else {
    UI.savedFiles.style.display = 'none';
  }
}

async function startRecording() {
  try {
    const response = await browser.runtime.sendMessage({
      action: 'startRecordingFromPopup'
    });

    if (response?.needsDevTools) {
      // Afficher un message plus visible
      showToast('Ouvrez DevTools (F12) et l\'onglet AutoHAR d\'abord');
    }
  } catch (e) {
    console.error('Erreur démarrage:', e);
    showToast('Erreur: ' + e.message);
  }
}

async function stopRecording() {
  try {
    await browser.runtime.sendMessage({
      action: 'stopRecordingFromPopup'
    });
  } catch (e) {
    console.error('Erreur arrêt:', e);
  }
}

function showToast(message) {
  // Supprimer le toast existant s'il y en a un
  const existingToast = document.getElementById('toast');
  if (existingToast) {
    existingToast.remove();
  }

  const toast = document.createElement('div');
  toast.id = 'toast';
  toast.className = 'toast';
  toast.textContent = message;
  document.body.appendChild(toast);

  // Supprimer après 3 secondes
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Injecter les styles pour les nouveaux éléments
const style = document.createElement('style');
style.textContent = `
  .devtools-warning {
    background: #4a3d2d;
    border-left: 3px solid #ffc107;
    border-radius: 4px;
    padding: 10px;
    margin-bottom: 12px;
    font-size: 11px;
    color: #ffc107;
  }

  .devtools-warning kbd {
    background: #3d3d3d;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
    color: #fff;
  }

  .status-value.disconnected {
    color: #ffc107 !important;
  }

  .toast {
    position: fixed;
    bottom: 16px;
    left: 16px;
    right: 16px;
    background: #dc3545;
    color: white;
    padding: 10px;
    border-radius: 4px;
    font-size: 11px;
    text-align: center;
    z-index: 1000;
    animation: slideIn 0.3s ease;
  }

  .toast.fade-out {
    animation: fadeOut 0.3s ease forwards;
  }

  @keyframes slideIn {
    from { transform: translateY(20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }

  @keyframes fadeOut {
    from { opacity: 1; }
    to { opacity: 0; }
  }
`;
document.head.appendChild(style);
