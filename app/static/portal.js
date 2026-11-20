document.addEventListener('DOMContentLoaded', () => {
  const toggle = document.querySelector('.menu-toggle');
  if (toggle) toggle.addEventListener('click', () => document.body.classList.toggle('nav-open'));
  document.querySelectorAll('.side-nav a').forEach(a => a.addEventListener('click', () => document.body.classList.remove('nav-open')));
});
