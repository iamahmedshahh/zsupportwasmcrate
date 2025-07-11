

function injectScript(filePath: string) {
  const script = document.createElement('script');
  script.setAttribute('type', 'module'); // This is the fix
  script.setAttribute('src', filePath);
  (document.head || document.documentElement).appendChild(script);
}
injectScript(chrome.runtime.getURL('inject.js'));