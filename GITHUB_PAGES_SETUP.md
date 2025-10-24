# 🌐 GitHub Pages Setup - Paso a Paso

**Problema:** Error 404 en https://fboiero.github.io/MIESC
**Causa:** GitHub Pages no está habilitado en la configuración del repositorio
**Solución:** Seguir estos pasos para habilitar GitHub Pages

---

## 📋 Pasos para Habilitar GitHub Pages

### Paso 1: Acceder a la Configuración del Repositorio

1. Abre tu navegador y ve a:
   ```
   https://github.com/fboiero/MIESC
   ```

2. Click en el botón **"Settings"** (⚙️ Configuración) en la parte superior derecha del repositorio

### Paso 2: Navegar a la Sección de Pages

1. En el menú lateral izquierdo, busca la sección **"Code and automation"**
2. Click en **"Pages"**
   - Está cerca del final de la lista, debajo de "Environments"

### Paso 3: Configurar el Source (Origen)

En la sección **"Build and deployment"**:

1. En **"Source"**, selecciona:
   ```
   Deploy from a branch
   ```

2. En **"Branch"**, selecciona:
   - **Branch:** `master` (o `main` si ese es tu branch principal)
   - **Folder:** `/ (root)`

3. Click en el botón **"Save"**

### Paso 4: Esperar el Despliegue

1. GitHub mostrará un mensaje:
   ```
   Your site is ready to be published at https://fboiero.github.io/MIESC/
   ```

2. Espera 2-3 minutos mientras GitHub construye el sitio

3. Refresca la página de Settings > Pages

4. Cuando esté listo, verás:
   ```
   ✅ Your site is live at https://fboiero.github.io/MIESC/
   ```

---

## 🔗 URLs que Estarán Disponibles

Una vez habilitado GitHub Pages:

- **Página Principal:** https://fboiero.github.io/MIESC/
- **Demo Interactivo:** https://fboiero.github.io/MIESC/demo-v3.3.0.html
- **Documentación:** https://fboiero.github.io/MIESC/docs/
- **README:** https://fboiero.github.io/MIESC/index.html

---

## ✅ Verificación

Para verificar que todo funciona:

1. Espera 2-3 minutos después de hacer "Save"
2. Abre en tu navegador: https://fboiero.github.io/MIESC/
3. Deberías ver la página principal de MIESC v3.3.0
4. Prueba también: https://fboiero.github.io/MIESC/demo-v3.3.0.html

---

## 🔧 Troubleshooting

### Si sigue dando 404:

1. **Verifica que guardaste los cambios:**
   - Vuelve a Settings > Pages
   - Confirma que Source esté configurado correctamente

2. **Espera más tiempo:**
   - El primer despliegue puede tardar hasta 10 minutos
   - Refresca la página cada minuto

3. **Verifica el branch:**
   - Asegúrate de que seleccionaste el branch correcto (master)
   - Los archivos index.html y demo-v3.3.0.html deben estar en la raíz

4. **Verifica el estado del despliegue:**
   - Ve a la pestaña "Actions" en GitHub
   - Busca el workflow "pages build and deployment"
   - Verifica que se ejecutó exitosamente (✅ verde)

### Si el workflow falla:

El archivo `.nojekyll` ya está en el repositorio para evitar conflictos con Jekyll.

Si aún hay problemas:
```bash
# Verifica que los archivos están en master
git checkout master
git pull origin master
ls -la index.html demo-v3.3.0.html .nojekyll
```

---

## 📊 Estado Actual

- ✅ Archivos HTML en la raíz del repositorio
- ✅ Archivo `.nojekyll` creado y pusheado
- ✅ Workflow de GitHub Actions configurado
- ⏳ **Falta:** Habilitar GitHub Pages en Settings (MANUAL)

---

## 🎯 Próximos Pasos Después de Habilitar

Una vez que GitHub Pages esté activo:

1. **Comparte el link:**
   - https://fboiero.github.io/MIESC/

2. **Actualiza la tesis:**
   - Incluye el link en tu documentación de tesis

3. **Actualiza el README:**
   - Añade badges de GitHub Pages

4. **Promociona:**
   - Comparte en redes sociales
   - LinkedIn
   - Twitter/X
   - Reddit (r/ethereum, r/ethdev)

---

## 📸 Capturas de Pantalla de Ayuda

### Ubicación del botón Settings:
```
GitHub Repo → Settings (esquina superior derecha)
```

### Ubicación de Pages en el menú:
```
Settings →
  ├─ General
  ├─ Access
  ├─ Branches
  ├─ ...
  ├─ Environments
  └─ Pages  ← AQUÍ
```

### Configuración correcta:
```
Build and deployment
  Source: Deploy from a branch
  Branch: master / (root)
  [Save] ← Hacer click aquí
```

---

**Última actualización:** October 20, 2025
**Repositorio:** https://github.com/fboiero/MIESC
**Autor:** Fernando Boiero (fboiero@frvm.utn.edu.ar)
