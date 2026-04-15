const DEFAULT_SETTINGS = {
  maxSizeMB: 5,
  saveLocation: 'autohar',
  includeTimestamp: true,
  notifyOnSave: true,
  autoStartOnDevTools: true,
  includeResponses: true
};

// Charger les paramètres
async function loadSettings() {
  const result = await browser.storage.local.get('settings');
  const settings = { ...DEFAULT_SETTINGS, ...result.settings };

  document.getElementById('maxSize').value = settings.maxSizeMB;
  document.getElementById('saveLocation').value = settings.saveLocation;
  document.getElementById('includeTimestamp').checked = settings.includeTimestamp;
  document.getElementById('notifyOnSave').checked = settings.notifyOnSave;
  document.getElementById('autoStart').checked = settings.autoStartOnDevTools;
  document.getElementById('includeResponses').checked = settings.includeResponses;
}

// Sauvegarder les paramètres
async function saveSettings() {
  const settings = {
    maxSizeMB: parseInt(document.getElementById('maxSize').value) || 5,
    saveLocation: document.getElementById('saveLocation').value || 'autohar',
    includeTimestamp: document.getElementById('includeTimestamp').checked,
    notifyOnSave: document.getElementById('notifyOnSave').checked,
    autoStartOnDevTools: document.getElementById('autoStart').checked,
    includeResponses: document.getElementById('includeResponses').checked
  };

  await browser.storage.local.set({ settings });

  // Afficher confirmation
  const msg = document.getElementById('savedMessage');
  msg.classList.add('show');
  setTimeout(() => msg.classList.remove('show'), 2000);
}

// Reset
function resetSettings() {
  browser.storage.local.set({ settings: DEFAULT_SETTINGS }).then(loadSettings);
}

// Events
document.getElementById('save').addEventListener('click', saveSettings);
document.getElementById('reset').addEventListener('click', resetSettings);

// Init
loadSettings();
