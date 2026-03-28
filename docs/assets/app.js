// Theme toggle
(function() {
    var saved = localStorage.getItem('infraudit-theme');
    if (saved) {
        document.documentElement.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: light)').matches) {
        document.documentElement.setAttribute('data-theme', 'light');
    }
})();

document.addEventListener('DOMContentLoaded', function() {
    // Mobile menu toggle
    var toggle = document.querySelector('.mobile-toggle');
    var navLinks = document.querySelector('.nav-links');
    var sidebarFooter = document.querySelector('.sidebar-footer');

    if (toggle) {
        toggle.addEventListener('click', function() {
            toggle.classList.toggle('active');
            navLinks.classList.toggle('open');
            if (sidebarFooter) sidebarFooter.classList.toggle('open');
        });
    }

    // Theme toggle
    var themeBtn = document.querySelector('.theme-toggle');
    if (themeBtn) {
        themeBtn.addEventListener('click', function() {
            var current = document.documentElement.getAttribute('data-theme');
            var next = current === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('infraudit-theme', next);
        });
    }

    // Scroll progress bar
    var progress = document.querySelector('.scroll-progress');
    if (progress) {
        window.addEventListener('scroll', function() {
            var h = document.documentElement;
            var pct = (h.scrollTop / (h.scrollHeight - h.clientHeight)) * 100;
            progress.style.width = pct + '%';
        });
    }

    // Back to top
    var btn = document.querySelector('.back-to-top');
    if (btn) {
        window.addEventListener('scroll', function() {
            if (window.scrollY > 400) {
                btn.classList.add('visible');
            } else {
                btn.classList.remove('visible');
            }
        });
    }
});
