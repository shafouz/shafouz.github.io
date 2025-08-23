window.addEventListener('load', function(event) {
  document.querySelectorAll('a[href^="http"]').forEach(link => {
    link.setAttribute('target', '_blank');
  });
});
