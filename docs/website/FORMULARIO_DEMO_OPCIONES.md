# 📋 Formulario de Demo - Opciones para Recibir Solicitudes

## 📍 Ubicación

**URL:** https://fboiero.github.io/MIESC/pages/demo-request.html
**Archivo:** `/Users/fboiero/Documents/GitHub/MIESC/pages/demo-request.html`

---

## ✅ Opción Actual (ACTIVADA)

### Email Automático via Cliente del Usuario

**Cómo funciona:**
1. Usuario llena el formulario
2. Hace clic en "Request Demo"
3. Se abre automáticamente su cliente de email (Gmail, Outlook, etc.)
4. Email pre-llenado con todos los datos
5. Usuario envía el email → **TÚ recibes el email en [email protected]**

**Ventajas:**
- ✅ Ya está activado (commit `488d8f8`)
- ✅ No requiere backend
- ✅ Gratis
- ✅ Funciona inmediatamente

**Desventajas:**
- ❌ Depende de que el usuario tenga cliente de email configurado
- ❌ Usuario debe hacer clic en "Enviar" en su email
- ❌ No hay base de datos de solicitudes

**Email que recibirás:**
```
Asunto: Demo Request from [Nombre del Usuario]

Demo Request Received
=====================

Personal Information:
---------------------
Name: John Doe
Email: [email protected]
Phone: +1 555 123 4567
Company: Acme Security Inc.
Role: Security Auditor

Interests:
----------
multi-agent-analysis, tool-integration

Use Case:
---------
We want to integrate MIESC into our audit workflow...

Project Details:
----------------
Contracts per month: 10-50
Languages: solidity, vyper
Timeline: Within 1 month

Additional Information:
-----------------------
Looking for CI/CD integration

Submitted: 2025-10-15T14:30:00.000Z
```

---

## 🎯 Opciones Más Profesionales

### Opción 2: FormSpree (⭐ Recomendada)

**Ventajas:**
- ✅ Gratis hasta 50 forms/mes
- ✅ Recibe emails automáticamente
- ✅ Dashboard web con todas las respuestas
- ✅ Export a CSV/Excel
- ✅ Integración con Slack, Zapier, Google Sheets
- ✅ Sin código backend necesario

**Setup (5 minutos):**

1. **Regístrate en FormSpree:**
   - Ve a: https://formspree.io/
   - Click "Sign Up" (puedes usar GitHub login)

2. **Crea un nuevo form:**
   - Click "New Form"
   - Nombre: "MIESC Demo Requests"
   - Email: [email protected]
   - Te dan un endpoint: `https://formspree.io/f/YOUR_FORM_ID`

3. **Modifica el formulario:**

Abre `pages/demo-request.html` y cambia la línea 206:

```html
<!-- ANTES: -->
<form id="demoForm" class="form-section">

<!-- DESPUÉS: -->
<form id="demoForm" class="form-section"
      action="https://formspree.io/f/YOUR_FORM_ID"
      method="POST">
```

4. **Comenta el JavaScript (opcional):**

Si quieres usar FormSpree nativo sin JavaScript, comenta las líneas 393-541.

O mejor, actualiza el fetch en línea 482:

```javascript
// Reemplaza línea 482-501 con:
fetch('https://formspree.io/f/YOUR_FORM_ID', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify(data)
})
.then(response => response.json())
.then(result => {
    document.getElementById('demoForm').style.display = 'none';
    document.getElementById('successMessage').style.display = 'block';
})
.catch(error => {
    console.error('Error:', error);
    alert('There was an error. Please email [email protected]');
    submitBtn.disabled = false;
    submitBtn.textContent = 'Request Demo';
});
```

5. **Recibirás:**
   - Email instantáneo con cada solicitud
   - Dashboard en formspree.io con todas las respuestas
   - Export a CSV

**Costo:**
- **Gratis:** 50 submissions/mes
- **Básico ($10/mes):** 1,000 submissions/mes + integraciones
- **Pro ($40/mes):** 10,000 submissions/mes + custom domain

---

### Opción 3: Google Forms

**Ventajas:**
- ✅ Completamente gratis
- ✅ Ilimitadas respuestas
- ✅ Google Sheets automático
- ✅ Notificaciones por email
- ✅ Muy fácil de configurar

**Setup (10 minutos):**

1. **Crea el form:**
   - Ve a: https://forms.google.com/
   - Click "+ Blank"
   - Agrega estos campos (mismos que el form actual):
     - Nombre (respuesta corta, obligatorio)
     - Email (respuesta corta, obligatorio)
     - Teléfono (respuesta corta, opcional)
     - Empresa (respuesta corta, obligatorio)
     - Rol (desplegable con opciones)
     - Intereses (casillas de verificación)
     - Caso de uso (párrafo, obligatorio)
     - Contratos por mes (desplegable)
     - Lenguajes (casillas)
     - Timeline (desplegable)
     - Info adicional (párrafo)

2. **Configura notificaciones:**
   - En el form, click en "Responses"
   - Click en el icono de los 3 puntos → "Get email notifications"

3. **Obtén el código embed:**
   - Click "Send"
   - Click en el icono `<>` (embed)
   - Copia el iframe code

4. **Reemplaza el form en demo-request.html:**

```html
<!-- Reemplaza líneas 206-362 con: -->
<div class="form-section">
    <iframe
        src="https://docs.google.com/forms/d/e/TU_FORM_ID/viewform?embedded=true"
        width="100%"
        height="2000"
        frameborder="0"
        marginheight="0"
        marginwidth="0"
        style="background: transparent;">
        Loading…
    </iframe>
</div>
```

5. **Styling (opcional):**

Puedes personalizar colores del Google Form:
- En el form, click en el icono de paleta (arriba)
- Sube una imagen de header (1600x400px)
- Selecciona color morado (#667eea) para match

**Recibirás:**
- Email cada vez que alguien llena el form
- Respuestas en Google Sheets en tiempo real
- Puedes agregar gráficos/analíticas

---

### Opción 4: Backend Propio (Avanzado)

Si quieres control total, necesitas:

**Requisitos:**
- Servidor (Heroku, Vercel, Railway, etc.)
- Base de datos (PostgreSQL, MongoDB, etc.)

**Stack sugerido:**

1. **Node.js + Express:**

```javascript
// server.js
const express = require('express');
const nodemailer = require('nodemailer');
const app = express();

app.post('/api/demo-request', async (req, res) => {
    const data = req.body;

    // Guardar en base de datos
    await db.demoRequests.insert(data);

    // Enviar email
    await transporter.sendMail({
        from: '[email protected]',
        to: '[email protected]',
        subject: `Demo Request from ${data.name}`,
        html: formatEmail(data)
    });

    res.json({ success: true });
});

app.listen(3000);
```

2. **Deploy:**
   - Heroku (gratis con límites)
   - Vercel (gratis para Hobby)
   - Railway (gratis $5 credit/mes)

3. **Actualiza el form:**

En `demo-request.html` línea 482, descomenta y actualiza:

```javascript
fetch('https://tu-dominio.com/api/demo-request', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify(data)
})
```

---

## 📊 Comparación de Opciones

| Característica | Email Actual | FormSpree | Google Forms | Backend Propio |
|---------------|--------------|-----------|--------------|----------------|
| **Setup** | ✅ Ya hecho | 5 min | 10 min | 2-4 horas |
| **Costo** | Gratis | Gratis-$10/mes | Gratis | $0-20/mes |
| **Emails automáticos** | ⚠️ Manual | ✅ Sí | ✅ Sí | ✅ Sí |
| **Dashboard** | ❌ No | ✅ Sí | ✅ Sí (Sheets) | ✅ Custom |
| **Base de datos** | ❌ No | ✅ Cloud | ✅ Sheets | ✅ Full control |
| **Export CSV** | ❌ No | ✅ Sí | ✅ Sí | ✅ Sí |
| **Integraciones** | ❌ No | ✅ Muchas | ✅ Zapier | ✅ Full control |
| **Branding** | ✅ Total | ✅ Total | ⚠️ Parcial | ✅ Total |
| **Confiabilidad** | ⚠️ Media | ✅ Alta | ✅ Muy alta | ⚠️ Depende |

---

## 🎯 Recomendación

**Para empezar ahora mismo:**
- ✅ Usa la opción actual (email automático) - Ya está activa

**Para más profesional (próximos días):**
- 🌟 **FormSpree** si quieres simplicidad + profesionalismo
- 🌟 **Google Forms** si quieres gratis + ilimitado

**Para futuro (cuando escales):**
- Backend propio con dashboard custom

---

## 🔍 Cómo Ver Solicitudes Actuales

### Método 1: Revisar Email
Revisa tu inbox: **[email protected]**

### Método 2: Ver localStorage (si usuarios lo usan)

Si quieres ver qué se guardó localmente cuando testing:

1. Abre el form: https://fboiero.github.io/MIESC/pages/demo-request.html
2. Abre la consola del navegador (F12)
3. Ve a la pestaña "Console"
4. Escribe:

```javascript
JSON.parse(localStorage.getItem('demoRequests'))
```

Esto te mostrará todas las solicitudes guardadas localmente.

**Nota:** Esto solo funciona en TU navegador para testing. Los datos de otros usuarios están en SUS navegadores.

---

## 🚀 Siguiente Paso Recomendado

Te sugiero implementar **FormSpree** porque:

1. **Tiempo:** 5 minutos
2. **Gratis:** Hasta 50 forms/mes (más que suficiente para empezar)
3. **Profesional:** Dashboard con todas las respuestas
4. **Sin backend:** No necesitas servidor
5. **Emails automáticos:** Recibes notificación instantánea

**Paso a paso:**

```bash
# 1. Regístrate en https://formspree.io/

# 2. Crea form y obtén ID

# 3. Actualiza demo-request.html:
# En línea 206, agrega:
# <form id="demoForm" action="https://formspree.io/f/YOUR_ID" method="POST">

# 4. En línea 482, descomenta y actualiza el endpoint

# 5. Commit y push:
git add pages/demo-request.html
git commit -m "Integrate FormSpree for demo requests"
git push origin main
```

---

## 📧 Emails que Recibirás

Con cualquier opción (excepto localStorage solo), recibirás emails como este:

```
De: FormSpree <[email protected]> (o tu email)
Para: [email protected]
Asunto: New Demo Request from John Doe

Name: John Doe
Email: [email protected]
Phone: +1 555 123 4567
Company: Acme Security Inc.
Role: Security Auditor
Interests: multi-agent-analysis, tool-integration
Use Case: We want to integrate MIESC...
Contracts/Month: 10-50
Languages: solidity, vyper
Timeline: Within 1 month
Additional: Looking for CI/CD integration
Submitted: 2025-10-15 14:30:00
```

---

## ❓ Preguntas Frecuentes

**P: ¿Cuántas solicitudes espero recibir?**
R: Para empezar, probablemente 1-5 por semana. FormSpree gratis (50/mes) es suficiente.

**P: ¿Puedo cambiar después?**
R: Sí, son cambios simples en el HTML. Puedes empezar con email y migrar a FormSpree cuando quieras.

**P: ¿Y si no recibo el email?**
R: Verifica spam. Con FormSpree, tienes el dashboard como backup.

**P: ¿Cómo proceso las solicitudes?**
R: Manual: revisas emails y respondes. Avanzado: integras con CRM via Zapier.

---

## 📞 Necesitas Ayuda?

Si quieres implementar FormSpree o Google Forms y necesitas ayuda:
- Avísame y te ayudo con el código exacto
- Puedo hacer el commit por ti con los cambios

---

**Estado Actual:** ✅ Email automático activado (commit `488d8f8`)
**Próximo paso sugerido:** Implementar FormSpree para dashboard profesional
