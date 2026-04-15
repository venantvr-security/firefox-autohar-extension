// Créer le panel PentestHAR dans les DevTools
// Note: La capture réseau est gérée dans panel.js pour éviter les doublons
browser.devtools.panels.create(
  'PentestHAR',
  '/icons/icon-48.png',
  '/devtools/panel.html'
).then(() => {
  console.log('PentestHAR panel created');
}).catch(error => {
  console.error('Failed to create PentestHAR panel:', error);
});
