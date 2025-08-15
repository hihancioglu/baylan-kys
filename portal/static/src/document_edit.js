document.addEventListener('DOMContentLoaded', () => {
  const cfg = Object.assign({}, window.editorConfig || {});
  cfg.events = {
    onDocumentStateChange: function (evt) {
      console.log('state changed', evt);
    },
    onSave: function (evt) {
      console.log('document saved', evt);
    },
    onRequestClose: function (evt) {
      console.log('editor closed', evt);
    }
  };
  if (window.editorToken && window.DocsAPI && window.DocsAPI.setRequestHeaders) {
    window.DocsAPI.setRequestHeaders([
      { header: window.editorTokenHeader, value: window.editorToken }
    ]);
  }
  window.docEditor = new DocsAPI.DocEditor('editor', cfg);
});
