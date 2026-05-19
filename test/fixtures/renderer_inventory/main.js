const { app, BrowserWindow, BrowserView, WebContentsView, session } = require('electron');

app.enableSandbox();

const isolatedSession = session.fromPartition('persist:builder-phase4');

function buildWindow() {
  const windowOptions = {
    webPreferences: {
      preload: '/preloads/main.js',
      partition: 'persist:main',
      sandbox: true,
      contextIsolation: true
    }
  };
  const mainWindow = new BrowserWindow(windowOptions);
  const contents = mainWindow.webContents;
  contents.on('will-navigate', () => {});
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
  contents.on('will-attach-webview', function(event, webPreferences, params) {
    event.preventDefault();
    delete webPreferences.preload;
    if (params.src === 'https://example.com/embed') {
      webPreferences.nodeIntegration = true;
    }
  });
  mainWindow.loadURL('https://example.com/app');
  return mainWindow;
}

const detailView = new BrowserView({
  webPreferences: {
    preload: '/preloads/view.js',
    session: isolatedSession
  }
});
detailView.webContents.loadURL('file:///view.html');

const embeddedView = new WebContentsView({
  webPreferences: {
    preload: '/preloads/contents.js',
    partition: 'persist:contents'
  }
});
embeddedView.webContents.on('new-window', () => {});
embeddedView.webContents.loadFile('renderer.html');

buildWindow();
