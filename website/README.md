# MIESC Project Website

Professional landing page and documentation hub for the MIESC (Multi-Agent Integrated Security Assessment Framework for Smart Contracts) project.

## 🌐 Live Preview

To view the website locally:

```bash
# Option 1: Python HTTP server
cd website
python -m http.server 8000
# Open http://localhost:8000

# Option 2: Node.js http-server
npx http-server website -p 8000

# Option 3: VS Code Live Server extension
# Right-click index.html → "Open with Live Server"
```

## 📁 Structure

```
website/
├── index.html          # Main landing page
├── css/
│   └── styles.css      # Modern, responsive stylesheet
├── js/
│   └── main.js         # Interactive features & animations
├── images/             # Project images and assets
├── pages/              # Additional documentation pages
└── README.md           # This file
```

## ✨ Features

### Design
- ✅ **Modern UI/UX** - Clean, professional design with tech aesthetic
- ✅ **Fully Responsive** - Mobile, tablet, and desktop optimized
- ✅ **Dark Theme** - Cybersecurity-inspired color scheme
- ✅ **Glass Morphism** - Semi-transparent cards with backdrop blur
- ✅ **Smooth Animations** - Scroll-triggered reveals and transitions
- ✅ **Color-Coded Layers** - Visual distinction for 6 security layers

### Sections
1. **Hero Section** - Project introduction with animated terminal
2. **Key Metrics** - 89.47% precision, 86.2% recall, 43% FP reduction
3. **Features** - Why developers choose MIESC
4. **Architecture** - 6-layer defense-in-depth visualization
5. **Tools** - 15 integrated security tools with badges
6. **Quick Start** - Installation tabs (Docker/pip/source)
7. **Research** - Scientific validation and benchmarks
8. **Documentation** - Links to guides and references

### Interactive Elements
- 🎯 **Mobile Menu** - Hamburger navigation for small screens
- 📋 **Copy Buttons** - One-click code copying with feedback
- 🔄 **Tab Switching** - Installation method tabs
- 🎨 **Smooth Scroll** - Navigation anchors scroll smoothly
- 👁️ **Scroll Animations** - Cards fade in as they enter viewport
- 🌙 **Dark Mode** - Theme toggle (future enhancement)
- ⬆️ **Scroll to Top** - Floating action button

## 🎨 Design System

### Colors

```css
/* Primary Colors */
--primary-blue: #0066cc;
--primary-teal: #00a8a8;
--dark-bg: #0a0e27;
--darker-bg: #060915;

/* Layer-Specific Colors */
--layer-1: #3b82f6;  /* Static - Blue */
--layer-2: #14b8a6;  /* Dynamic - Teal */
--layer-3: #a855f7;  /* Symbolic - Purple */
--layer-4: #10b981;  /* Formal - Green */
--layer-5: #f59e0b;  /* AI - Amber */
--layer-6: #ef4444;  /* Policy - Red */

/* Status Colors */
--success: #10b981;
--warning: #f59e0b;
--critical: #ef4444;
```

### Typography

- **Headings**: Inter (300-800 weight)
- **Body**: Inter (400-600 weight)
- **Code**: JetBrains Mono (400-600 weight)

### Breakpoints

- Mobile: < 768px
- Tablet: 768px - 1024px
- Desktop: > 1024px

## 🚀 Deployment

### GitHub Pages

```bash
# Enable GitHub Pages in repository settings
# Set source to: main branch → /website folder
```

### Netlify

```bash
# netlify.toml
[build]
  publish = "website"
  command = "echo 'Static site, no build needed'"

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

### Vercel

```bash
# vercel.json
{
  "buildCommand": "echo 'Static site'",
  "outputDirectory": "website",
  "cleanUrls": true
}
```

### Custom Domain

Add CNAME record pointing to your hosting provider:
```
miesc.yourdomain.com → your-hosting-provider
```

## 🔧 Customization

### Update Metrics

Edit `index.html`, search for `.metric-value` classes:

```html
<div class="metric-value">89.47%</div>
<div class="metric-label">Precision</div>
```

### Add New Section

1. Add section to `index.html`:
```html
<section class="new-section" id="newsection">
  <div class="container">
    <h2 class="section-title">New Section</h2>
    <!-- Content here -->
  </div>
</section>
```

2. Add navigation link:
```html
<li><a href="#newsection">New Section</a></li>
```

3. Add styles to `styles.css`:
```css
.new-section {
  padding: 80px 0;
  background: var(--dark-bg);
}
```

### Change Colors

Edit CSS variables in `styles.css`:

```css
:root {
  --primary-blue: #your-color;
  --primary-teal: #your-color;
}
```

## 📊 Analytics (Optional)

Add Google Analytics or Plausible:

```html
<!-- Before </head> -->
<script async src="https://www.googletagmanager.com/gtag/js?id=GA_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA_ID');
</script>
```

## 🐛 Known Issues

None currently. Please report issues at: https://github.com/fboiero/xaudit/issues

## 📝 Todo

- [ ] Add blog section for security updates
- [ ] Create interactive demo/playground page
- [ ] Add video tutorials
- [ ] Implement search functionality
- [ ] Add changelog page
- [ ] Create case studies section
- [ ] Multilingual support (Spanish, Chinese)

## 🤝 Contributing

Improvements to the website are welcome! Areas for contribution:

1. **Design** - Improve UI/UX, animations, or responsiveness
2. **Content** - Add tutorials, examples, or documentation
3. **Performance** - Optimize images, lazy loading, caching
4. **Accessibility** - Improve ARIA labels, keyboard navigation
5. **Features** - Interactive demos, visualizations, tools

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## 📄 License

GPL-3.0 - Same as the main MIESC project

## 👤 Author

**Fernando Boiero**
- Email: fboiero@frvm.utn.edu.ar
- GitHub: [@fboiero](https://github.com/fboiero)
- Institution: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba

---

**Last Updated**: October 2024
**Version**: 2.2.0
**Status**: 🚀 Production Ready
