// PentestHAR Background Script
// Gère la sauvegarde des fichiers HAR et la communication avec le DevTools panel

const DEFAULT_SETTINGS = {
  enabled: true,
  maxSizeMB: 5,
  saveLocation: 'pentesthar',
  includeTimestamp: true,
  notifyOnSave: true,
  autoStartOnDevTools: true
};

let settings = { ...DEFAULT_SETTINGS };
let panelConnected = false;
let panelLastSeen = 0;
const PANEL_TIMEOUT_MS = 5000; // Considérer le panel déconnecté après 5s sans signal

// Charger les paramètres au démarrage
browser.storage.local.get('settings').then(result => {
  if (result.settings) {
    settings = { ...DEFAULT_SETTINGS, ...result.settings };
  }
});

// Écouter les changements de paramètres
browser.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.settings) {
    settings = { ...DEFAULT_SETTINGS, ...changes.settings.newValue };
  }
});

// Vérifier si le panel est considéré comme connecté
function isPanelConnected() {
  return panelConnected && (Date.now() - panelLastSeen < PANEL_TIMEOUT_MS);
}

// Gérer les messages du DevTools panel et du Popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'getSettings':
      sendResponse(settings);
      return true;

    case 'panelReady':
      panelConnected = true;
      panelLastSeen = Date.now();
      sendResponse({ success: true });
      return true;

    case 'saveHAR':
      // Le panel envoie des données = il est connecté
      panelConnected = true;
      panelLastSeen = Date.now();
      saveHARFile(message.data, message.metadata)
        .then(result => sendResponse(result))
        .catch(error => sendResponse({ success: false, error: error.message }));
      return true;

    case 'updateStats':
      // Le panel envoie des stats = il est connecté
      panelConnected = true;
      panelLastSeen = Date.now();
      updateBadge(message.requestCount, message.sizeMB);
      return true;

    case 'notifySaved':
      if (settings.notifyOnSave) {
        showNotification(message.filename, message.sizeMB);
      }
      return true;

    case 'getPanelStatus':
      sendResponse({
        connected: isPanelConnected(),
        lastSeen: panelLastSeen
      });
      return true;

    case 'startRecordingFromPopup':
      // Stocker la commande pour que le panel la récupère
      browser.storage.local.set({ recordingCommand: 'start' });

      // Essayer d'envoyer directement au panel s'il est connecté
      if (isPanelConnected()) {
        browser.runtime.sendMessage({
          action: 'startRecordingCommand'
        }).then(() => {
          sendResponse({ success: true, panelConnected: true });
        }).catch(() => {
          sendResponse({ success: true, panelConnected: false, needsDevTools: true });
        });
      } else {
        sendResponse({ success: true, panelConnected: false, needsDevTools: true });
      }
      return true;

    case 'stopRecordingFromPopup':
      // Stocker la commande pour que le panel la récupère
      browser.storage.local.set({ recordingCommand: 'stop' });

      // Essayer d'envoyer directement au panel s'il est connecté
      if (isPanelConnected()) {
        browser.runtime.sendMessage({
          action: 'stopRecordingCommand'
        }).then(() => {
          sendResponse({ success: true, panelConnected: true });
        }).catch(() => {
          sendResponse({ success: true, panelConnected: false });
        });
      } else {
        sendResponse({ success: true, panelConnected: false });
      }
      return true;

    case 'startRecordingCommand':
    case 'stopRecordingCommand':
      // Relayé depuis le popup - le panel va gérer
      sendResponse({ success: true });
      return true;
  }
});

async function saveHARFile(harData, metadata = {}) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const domain = metadata.domain || 'unknown';
  const filename = settings.includeTimestamp
    ? `${settings.saveLocation}/${domain}_${timestamp}.har`
    : `${settings.saveLocation}/${domain}_${Date.now()}.har`;

  const blob = new Blob([JSON.stringify(harData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  try {
    const downloadId = await browser.downloads.download({
      url: url,
      filename: filename,
      saveAs: false,
      conflictAction: 'uniquify'
    });

    // Nettoyer l'URL blob après le téléchargement
    setTimeout(() => URL.revokeObjectURL(url), 10000);

    return { success: true, downloadId, filename };
  } catch (error) {
    URL.revokeObjectURL(url);
    throw error;
  }
}

function updateBadge(requestCount, sizeMB) {
  const text = sizeMB >= 1 ? `${sizeMB.toFixed(1)}M` : `${requestCount}`;
  browser.browserAction.setBadgeText({ text });

  // Couleur selon la taille
  const color = sizeMB >= settings.maxSizeMB * 0.8 ? '#dc3545' : '#198754';
  browser.browserAction.setBadgeBackgroundColor({ color });
}

function showNotification(filename, sizeMB) {
  browser.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-96.png',
    title: 'PentestHAR - Sauvegarde effectuée',
    message: `${filename}\nTaille: ${sizeMB.toFixed(2)} Mo`
  });
}
