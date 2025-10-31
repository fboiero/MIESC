# MIESC Website

Official website for the MIESC (Marco Integrado de Evaluación de Seguridad en Smart Contracts) framework.

## 🌐 Live Site

**Production**: https://fboiero.github.io/xaudit/

## 📁 Structure

```
docs/website/
├── index.html          # Main landing page
├── css/
│   └── styles.css      # Modern, responsive CSS
├── js/
│   └── main.js         # Interactive features
├── assets/
│   ├── visualizations/ # Benchmark charts and graphs
│   └── images/         # Logo, icons, etc.
└── README.md           # This file
```

## 🚀 Local Development

### Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/fboiero/xaudit.git
   cd xaudit/docs/website
   ```

2. **Open in browser**:
   ```bash
   # Option 1: Direct open
   open index.html

   # Option 2: Python HTTP server
   python -m http.server 8000
   # Visit: http://localhost:8000

   # Option 3: Node.js http-server
   npx http-server -p 8000
   ```

### Live Reload (Optional)

```bash
# Install live-server globally
npm install -g live-server

# Run with auto-reload
cd docs/website
live-server
```

## 🎨 Design

### Technology Stack

- **HTML5**: Semantic markup
- **CSS3**: Modern features (Grid, Flexbox, Custom Properties)
- **Vanilla JavaScript**: No framework dependencies
- **Responsive Design**: Mobile-first approach

### Color Scheme

```css
Primary: #2563eb (Blue)
Secondary: #10b981 (Green)
Accent: #8b5cf6 (Purple)
Background: #ffffff / #f9fafb
Text: #111827 / #6b7280
```

### Typography

- **Sans-serif**: Inter
- **Monospace**: JetBrains Mono

### Fonts (Google Fonts)

Loaded from CDN in `index.html`:
```html
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
```

## 🔧 Customization

### Updating Content

1. **Hero Section**: Edit `index.html` lines 50-120
2. **Features**: Modify `.features-grid` section
3. **Benchmarks**: Update tables and add images to `assets/visualizations/`
4. **Documentation Links**: Update `.docs-grid` with new doc pages

### Adding New Sections

1. Create new `<section>` in `index.html`
2. Add corresponding styles in `css/styles.css`
3. Update navigation links in header

### Updating Visualizations

```bash
# Regenerate visualizations in main project
cd ../..
python visualize_comparison.py

# Copy to website
cp outputs/visualizations/* docs/website/assets/visualizations/
```

## 📦 Deployment

### GitHub Pages (Current)

**Automatic deployment** on push to `main` branch.

#### Manual Setup (if needed):

1. Go to: https://github.com/fboiero/xaudit/settings/pages
2. Source: Deploy from a branch
3. Branch: `main`
4. Folder: `/docs/website`
5. Save

GitHub Actions will build and deploy automatically.

### Alternative Hosting

#### Netlify

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
cd docs/website
netlify deploy --prod
```

**Deploy settings**:
- Build command: (none needed - static site)
- Publish directory: `docs/website`

#### Vercel

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
cd docs/website
vercel --prod
```

#### CloudFlare Pages

1. Connect GitHub repository
2. Build settings:
   - Build command: (none)
   - Build output: `docs/website`
3. Deploy

## 🔍 SEO Optimization

### Meta Tags

All essential meta tags included in `<head>`:
- Description
- Keywords
- Open Graph (social media)
- Twitter Card
- Canonical URL

### Sitemap (Optional)

Create `sitemap.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://fboiero.github.io/xaudit/</loc>
    <lastmod>2025-10-12</lastmod>
    <priority>1.0</priority>
  </url>
</urlset>
```

### robots.txt

Create `robots.txt`:
```
User-agent: *
Allow: /
Sitemap: https://fboiero.github.io/xaudit/sitemap.xml
```

## ♿ Accessibility

### Features Implemented

- ✅ Semantic HTML5 elements
- ✅ ARIA labels where needed
- ✅ Keyboard navigation support
- ✅ Focus indicators
- ✅ Reduced motion support (`prefers-reduced-motion`)
- ✅ Sufficient color contrast (WCAG AA)
- ✅ Alt text for images

### Testing

```bash
# Lighthouse audit
npx lighthouse https://fboiero.github.io/xaudit/ --view

# Accessibility testing
npx pa11y https://fboiero.github.io/xaudit/
```

## 📊 Analytics (Optional)

### Google Analytics 4

Add to `<head>` of `index.html`:
```html
<!-- Google tag (gtag.js) -->
<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXXXXXXXX"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'G-XXXXXXXXXX');
</script>
```

### Privacy-Focused Alternatives

- **Plausible**: Lightweight, GDPR compliant
- **Umami**: Self-hosted, open source
- **Fathom**: Simple, privacy-first

## 🐛 Troubleshooting

### Images Not Loading

```bash
# Check file paths
ls docs/website/assets/visualizations/

# Verify image references in HTML
grep -r "visualizations" docs/website/index.html
```

### Styles Not Applied

1. Check browser console for CSS errors
2. Verify `styles.css` path in HTML
3. Clear browser cache (Cmd+Shift+R / Ctrl+Shift+R)

### GitHub Pages Not Updating

1. Check Actions tab: https://github.com/fboiero/xaudit/actions
2. Verify branch and folder settings
3. Wait 2-3 minutes for propagation
4. Hard refresh browser: Cmd+Shift+R / Ctrl+F5

## 📝 Maintenance

### Regular Updates

- [ ] Update benchmark visualizations quarterly
- [ ] Refresh compliance status
- [ ] Add new documentation links
- [ ] Update year in footer
- [ ] Review broken links
- [ ] Check mobile responsiveness

### Performance Optimization

```bash
# Minify CSS
npx clean-css-cli -o css/styles.min.css css/styles.css

# Minify JavaScript
npx terser js/main.js -o js/main.min.js

# Optimize images
npx imagemin assets/**/* --out-dir=assets/optimized
```

## 🤝 Contributing

To improve the website:

1. Fork the repository
2. Create feature branch: `git checkout -b website-improvements`
3. Make changes to `docs/website/`
4. Test locally
5. Commit: `git commit -m "Improve website XYZ"`
6. Push: `git push origin website-improvements`
7. Create Pull Request

## 📧 Contact

**Website Issues**: Open issue at https://github.com/fboiero/xaudit/issues

**General Contact**:
- Fernando Boiero
- Email: fboiero@frvm.utn.edu.ar
- GitHub: @fboiero

---

**Last Updated**: October 12, 2025
**Version**: 1.0
**Status**: Production
**License**: GPL-3.0 (same as main project)
