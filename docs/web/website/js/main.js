/**
 * MIESC - Main JavaScript
 * Multi-Agent Security Framework for Smart Contracts
 * Interactive functionality for the website
 */

// ============================================
// MOBILE MENU TOGGLE
// ============================================
function initMobileMenu() {
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const navLinks = document.querySelector('.nav-links');

  if (mobileMenuBtn && navLinks) {
    mobileMenuBtn.addEventListener('click', () => {
      mobileMenuBtn.classList.toggle('active');
      navLinks.classList.toggle('active');
    });

    // Close menu when clicking a link
    const navLinkItems = navLinks.querySelectorAll('a');
    navLinkItems.forEach(link => {
      link.addEventListener('click', () => {
        mobileMenuBtn.classList.remove('active');
        navLinks.classList.remove('active');
      });
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
      if (!mobileMenuBtn.contains(e.target) && !navLinks.contains(e.target)) {
        mobileMenuBtn.classList.remove('active');
        navLinks.classList.remove('active');
      }
    });
  }
}

// ============================================
// TAB SWITCHING (QUICKSTART SECTION)
// ============================================
function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const targetTab = button.getAttribute('data-tab');

      // Remove active class from all buttons and contents
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabContents.forEach(content => content.classList.remove('active'));

      // Add active class to clicked button
      button.classList.add('active');

      // Show corresponding content
      const targetContent = document.getElementById(`${targetTab}-tab`);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });
}

// ============================================
// COPY TO CLIPBOARD
// ============================================
function initCopyButtons() {
  const copyButtons = document.querySelectorAll('.copy-btn');

  copyButtons.forEach(button => {
    button.addEventListener('click', async () => {
      const targetSelector = button.getAttribute('data-clipboard-target');
      const targetElement = document.querySelector(targetSelector);

      if (targetElement) {
        try {
          // Get text content
          const textToCopy = targetElement.textContent || targetElement.innerText;

          // Copy to clipboard using modern API
          if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(textToCopy);
          } else {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = textToCopy;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
          }

          // Visual feedback
          const originalText = button.textContent;
          button.textContent = 'Copied!';
          button.classList.add('copied');

          // Reset after 2 seconds
          setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('copied');
          }, 2000);
        } catch (err) {
          console.error('Failed to copy text:', err);
          button.textContent = 'Failed';
          setTimeout(() => {
            button.textContent = 'Copy';
          }, 2000);
        }
      }
    });
  });
}

// ============================================
// SMOOTH SCROLL FOR NAVIGATION LINKS
// ============================================
function initSmoothScroll() {
  const navLinks = document.querySelectorAll('a[href^="#"]');

  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      const href = link.getAttribute('href');

      // Only prevent default for anchor links (not just "#")
      if (href && href !== '#' && href.startsWith('#')) {
        const targetId = href.substring(1);
        const targetElement = document.getElementById(targetId);

        if (targetElement) {
          e.preventDefault();

          // Calculate offset for sticky navbar
          const navbar = document.querySelector('.navbar');
          const navbarHeight = navbar ? navbar.offsetHeight : 0;
          const targetPosition = targetElement.offsetTop - navbarHeight - 20;

          window.scrollTo({
            top: targetPosition,
            behavior: 'smooth'
          });
        }
      }
    });
  });
}

// ============================================
// ACTIVE NAV LINK HIGHLIGHTING ON SCROLL
// ============================================
function initActiveNavHighlight() {
  const sections = document.querySelectorAll('section[id]');
  const navLinks = document.querySelectorAll('.nav-links a[href^="#"]');

  function highlightActiveSection() {
    const scrollPosition = window.scrollY + 100; // Offset for navbar

    sections.forEach(section => {
      const sectionTop = section.offsetTop;
      const sectionHeight = section.offsetHeight;
      const sectionId = section.getAttribute('id');

      if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
        navLinks.forEach(link => {
          link.classList.remove('active');
          if (link.getAttribute('href') === `#${sectionId}`) {
            link.classList.add('active');
          }
        });
      }
    });
  }

  // Throttle scroll event for performance
  let scrollTimeout;
  window.addEventListener('scroll', () => {
    if (scrollTimeout) {
      window.cancelAnimationFrame(scrollTimeout);
    }
    scrollTimeout = window.requestAnimationFrame(highlightActiveSection);
  });

  // Initial check
  highlightActiveSection();
}

// ============================================
// NAVBAR SCROLL EFFECT
// ============================================
function initNavbarScroll() {
  const navbar = document.querySelector('.navbar');
  let lastScroll = 0;

  window.addEventListener('scroll', () => {
    const currentScroll = window.pageYOffset;

    if (currentScroll > 50) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }

    lastScroll = currentScroll;
  });
}

// ============================================
// INTERSECTION OBSERVER FOR SCROLL ANIMATIONS
// ============================================
function initScrollAnimations() {
  // Create observer for fade-in animations
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        // Optionally unobserve after animation
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);

  // Observe all cards and sections
  const elementsToAnimate = document.querySelectorAll(`
    .metric-card,
    .feature-card,
    .tool-card,
    .doc-card,
    .research-card,
    .workflow-step,
    .arch-layer-card
  `);

  elementsToAnimate.forEach(el => {
    el.classList.add('scroll-animate');
    observer.observe(el);
  });
}

// ============================================
// TERMINAL ANIMATION (HERO SECTION)
// ============================================
function initTerminalAnimation() {
  const terminalLines = document.querySelectorAll('.scan-line');

  terminalLines.forEach((line, index) => {
    line.style.animationDelay = `${index * 0.3}s`;
  });
}

// ============================================
// THEME TOGGLE (DARK/LIGHT MODE)
// ============================================
function initThemeToggle() {
  const themeToggleBtn = document.getElementById('themeToggle');

  if (themeToggleBtn) {
    // Check for saved theme preference or default to dark
    const currentTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);

    themeToggleBtn.addEventListener('click', () => {
      const theme = document.documentElement.getAttribute('data-theme');
      const newTheme = theme === 'dark' ? 'light' : 'dark';

      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
    });
  }
}

// ============================================
// FLOATING ACTION BUTTON (SCROLL TO TOP)
// ============================================
function initScrollToTop() {
  // Create scroll-to-top button if it doesn't exist
  let scrollBtn = document.getElementById('scrollToTop');

  if (!scrollBtn) {
    scrollBtn = document.createElement('button');
    scrollBtn.id = 'scrollToTop';
    scrollBtn.innerHTML = '↑';
    scrollBtn.setAttribute('aria-label', 'Scroll to top');
    scrollBtn.style.cssText = `
      position: fixed;
      bottom: 30px;
      right: 30px;
      width: 50px;
      height: 50px;
      border-radius: 50%;
      background: linear-gradient(135deg, var(--color-primary), var(--color-secondary));
      color: white;
      border: none;
      font-size: 24px;
      cursor: pointer;
      opacity: 0;
      visibility: hidden;
      transition: all 0.3s ease;
      box-shadow: var(--shadow-lg);
      z-index: var(--z-fixed);
    `;
    document.body.appendChild(scrollBtn);
  }

  // Show/hide button based on scroll position
  window.addEventListener('scroll', () => {
    if (window.pageYOffset > 500) {
      scrollBtn.style.opacity = '1';
      scrollBtn.style.visibility = 'visible';
    } else {
      scrollBtn.style.opacity = '0';
      scrollBtn.style.visibility = 'hidden';
    }
  });

  // Scroll to top when clicked
  scrollBtn.addEventListener('click', () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  });

  // Hover effect
  scrollBtn.addEventListener('mouseenter', () => {
    scrollBtn.style.transform = 'translateY(-5px)';
  });

  scrollBtn.addEventListener('mouseleave', () => {
    scrollBtn.style.transform = 'translateY(0)';
  });
}

// ============================================
// SYNTAX HIGHLIGHTING FOR CODE BLOCKS
// ============================================
function initSyntaxHighlighting() {
  const codeBlocks = document.querySelectorAll('pre code');

  codeBlocks.forEach(block => {
    // Add line numbers if not already present
    if (!block.classList.contains('has-line-numbers')) {
      const lines = block.textContent.split('\n');
      if (lines.length > 1) {
        const numberedHTML = lines.map((line, index) => {
          return `<span class="line-number">${index + 1}</span>${escapeHtml(line)}`;
        }).join('\n');
        // block.innerHTML = numberedHTML; // Uncomment if you want line numbers
        block.classList.add('has-line-numbers');
      }
    }
  });
}

// Helper function to escape HTML
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

// ============================================
// KEYBOARD NAVIGATION
// ============================================
function initKeyboardNavigation() {
  document.addEventListener('keydown', (e) => {
    // Escape key closes mobile menu
    if (e.key === 'Escape') {
      const mobileMenuBtn = document.getElementById('mobileMenuBtn');
      const navLinks = document.querySelector('.nav-links');

      if (mobileMenuBtn && navLinks) {
        mobileMenuBtn.classList.remove('active');
        navLinks.classList.remove('active');
      }
    }
  });
}

// ============================================
// PERFORMANCE MONITORING
// ============================================
function logPerformanceMetrics() {
  if (window.performance && window.performance.timing) {
    window.addEventListener('load', () => {
      setTimeout(() => {
        const perfData = window.performance.timing;
        const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
        const connectTime = perfData.responseEnd - perfData.requestStart;
        const renderTime = perfData.domComplete - perfData.domLoading;

        console.log('MIESC Website Performance:');
        console.log(`Page Load Time: ${pageLoadTime}ms`);
        console.log(`Connect Time: ${connectTime}ms`);
        console.log(`Render Time: ${renderTime}ms`);
      }, 0);
    });
  }
}

// ============================================
// ANALYTICS (PLACEHOLDER)
// ============================================
function initAnalytics() {
  // Track page views
  const trackPageView = () => {
    // Add your analytics code here (Google Analytics, Plausible, etc.)
    console.log('Page view tracked:', window.location.pathname);
  };

  // Track button clicks
  const trackButtonClick = (buttonName) => {
    console.log('Button clicked:', buttonName);
    // Add your analytics tracking code here
  };

  // Add click tracking to primary buttons
  const primaryButtons = document.querySelectorAll('.btn-primary');
  primaryButtons.forEach(button => {
    button.addEventListener('click', () => {
      trackButtonClick(button.textContent);
    });
  });

  trackPageView();
}

// ============================================
// EASTER EGG: KONAMI CODE
// ============================================
function initEasterEgg() {
  const konamiCode = [
    'ArrowUp', 'ArrowUp', 'ArrowDown', 'ArrowDown',
    'ArrowLeft', 'ArrowRight', 'ArrowLeft', 'ArrowRight',
    'KeyB', 'KeyA'
  ];
  let konamiIndex = 0;

  document.addEventListener('keydown', (e) => {
    if (e.code === konamiCode[konamiIndex]) {
      konamiIndex++;
      if (konamiIndex === konamiCode.length) {
        activateEasterEgg();
        konamiIndex = 0;
      }
    } else {
      konamiIndex = 0;
    }
  });

  function activateEasterEgg() {
    // Fun animation or message
    const originalTitle = document.title;
    document.title = '🛡️ MIESC ULTRA MODE ACTIVATED! 🚀';

    // Add rainbow effect to hero title
    const heroTitle = document.querySelector('.hero-title');
    if (heroTitle) {
      heroTitle.style.animation = 'rainbow 2s linear infinite';
    }

    // Add CSS for rainbow animation if not exists
    if (!document.getElementById('easter-egg-styles')) {
      const style = document.createElement('style');
      style.id = 'easter-egg-styles';
      style.textContent = `
        @keyframes rainbow {
          0% { filter: hue-rotate(0deg); }
          100% { filter: hue-rotate(360deg); }
        }
      `;
      document.head.appendChild(style);
    }

    // Show console message
    console.log('%c🎉 MIESC ULTRA MODE ACTIVATED! 🎉', 'font-size: 24px; color: #00a8a8; font-weight: bold;');
    console.log('%cYou found the secret! 🕵️', 'font-size: 16px; color: #0066cc;');
    console.log('%cMIESC Team appreciates your curiosity!', 'font-size: 14px; color: #10b981;');

    // Reset after 5 seconds
    setTimeout(() => {
      document.title = originalTitle;
      if (heroTitle) {
        heroTitle.style.animation = '';
      }
    }, 5000);
  }
}

// ============================================
// LAZY LOADING IMAGES
// ============================================
function initLazyLoading() {
  const images = document.querySelectorAll('img[data-src]');

  const imageObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        img.src = img.dataset.src;
        img.removeAttribute('data-src');
        imageObserver.unobserve(img);
      }
    });
  });

  images.forEach(img => imageObserver.observe(img));
}

// ============================================
// VIEWPORT HEIGHT FIX (FOR MOBILE)
// ============================================
function initViewportFix() {
  // Fix for mobile viewport height (100vh issue)
  const setVH = () => {
    const vh = window.innerHeight * 0.01;
    document.documentElement.style.setProperty('--vh', `${vh}px`);
  };

  setVH();
  window.addEventListener('resize', setVH);
}

// ============================================
// INITIALIZE ALL FUNCTIONS
// ============================================
function init() {
  console.log('%c🛡️ MIESC Website Loaded', 'font-size: 16px; color: #0066cc; font-weight: bold;');
  console.log('%cMulti-Agent Security Framework for Smart Contracts', 'font-size: 12px; color: #00a8a8;');
  console.log('%cVersion 2.2.0 | GPL-3.0 License', 'font-size: 10px; color: #9ca3af;');

  // Core functionality
  initMobileMenu();
  initTabs();
  initCopyButtons();
  initSmoothScroll();
  initActiveNavHighlight();
  initNavbarScroll();
  initScrollAnimations();
  initTerminalAnimation();
  initThemeToggle();
  initScrollToTop();
  initSyntaxHighlighting();
  initKeyboardNavigation();
  initLazyLoading();
  initViewportFix();

  // Optional features
  initAnalytics();
  initEasterEgg();
  logPerformanceMetrics();

  console.log('%c✅ All systems initialized', 'font-size: 12px; color: #10b981; font-weight: bold;');
}

// ============================================
// START THE APPLICATION
// ============================================
// Wait for DOM to be fully loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  // DOM is already loaded
  init();
}

// ============================================
// EXPORT FOR MODULE USAGE (IF NEEDED)
// ============================================
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    init,
    initMobileMenu,
    initTabs,
    initCopyButtons,
    initSmoothScroll,
    initScrollAnimations
  };
}
