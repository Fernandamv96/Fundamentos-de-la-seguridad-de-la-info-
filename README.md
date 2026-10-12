# 🔐 Auditoría CIA: sistemas INACAP (simulación)

[![CI](https://github.com/Fernandamv96/Fundamentos-de-la-seguridad-de-la-info-/actions/workflows/ci.yml/badge.svg)](https://github.com/Fernandamv96/Fundamentos-de-la-seguridad-de-la-info-/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Fernandamv96/Fundamentos-de-la-seguridad-de-la-info-/actions/workflows/codeql.yml/badge.svg)](https://github.com/Fernandamv96/Fundamentos-de-la-seguridad-de-la-info-/actions/workflows/codeql.yml)
![Python](https://img.shields.io/badge/Python-3.10+-BD93F9?logo=python&logoColor=white)
[![License: MIT](https://img.shields.io/badge/License-MIT-FF79C6)](LICENSE)

Informe práctico del ramo **Fundamentos de la Seguridad de la Información (INACAP)**. Simula, en Python y en una página HTML interactiva, los controles de seguridad que propongo para la Intranet, INACAPMail y el LMS (Moodle).

> Es una **simulación educativa**: no se conecta a ningún sistema real y todos los RUT y datos son ficticios.

## Objetivo

Responder las tres preguntas de la actividad grupal, una por cada principio de la **tríada CIA**:

| Principio | Pregunta | Qué simula el código |
|-----------|----------|----------------------|
| **Confidencialidad** | ¿Cómo evitar que un alumno vea enfermedades preexistentes, ingresos familiares o FUAS de otros? | `ControlDeAcceso`: RBAC con **denegación por defecto**, separación por RUT y log de auditoría de cada intento |
| **Integridad** | ¿Cómo detectar o prevenir que un alumno altere notas o asistencia? | `SistemaIntegridad`: hash SHA-256 por registro, historial de cambios con autor y reversión de cambios no autorizados |
| **Disponibilidad** | ¿Qué impacto tiene que caigan INACAPMail, Moodle e Intranet en semana de exámenes? | `SimuladorDisponibilidad`: ataque DDoS simulado, usuarios afectados y plan de continuidad (BCP) paso a paso |

## Cómo ejecutarlo

**Script (Python 3.10+, solo biblioteca estándar):**

```bash
python auditoria_seguridad_inacap.py
```

> En la consola de Windows, si ves errores con los emojis, usa `set PYTHONIOENCODING=utf-8` (o Windows Terminal).

**Simulador interactivo:** abre `auditoria_seguridad_inacap.html` en el navegador.

**Tests y lint:**

```bash
pip install -r requirements-dev.txt
pytest
ruff check . && ruff format --check .
```

## Ejemplo de salida

```text
  1. CONFIDENCIALIDAD — Control de Acceso a Datos Sensibles
============================================================
  LOG DE AUDITORÍA — CONTROL DE ACCESO
============================================================
[2026-10-12T08:16:41.332880] 🚫 DENEGADO
  Usuario : 12345678-9 (alumno)
  Recurso : fuas_ajeno  |  Objetivo: 98765432-1
  IP      : 192.168.1.19
------------------------------------------------------------
[2026-10-12T08:16:41.332972] ✅ PERMITIDO
  Usuario : 12345678-9 (alumno)
  Recurso : notas_propias  |  Objetivo: 12345678-9

  2. INTEGRIDAD — Detección de Alteración de Notas/Asistencia
[INTEGRIDAD] Registro creado para RUT 12345678-9  |  Hash: c6cf8e8b5c7feead3ec9...
[INTEGRIDAD] Modificación AUTORIZADA aceptada para 12345678-9.

🚨 [ALERTA INTEGRIDAD] Modificación NO AUTORIZADA detectada.
   Campo   : nota_1  |  3.5 → 7.0
   Acción  : Cambio REVERTIDO. Notificación enviada al área de seguridad.
[VERIFICACIÓN] RUT 12345678-9: ✅ ÍNTEGRO
```

## Estructura

```text
├── auditoria_seguridad_inacap.py    # simulación de los 3 principios CIA
├── auditoria_seguridad_inacap.html  # versión interactiva (simulador en el navegador)
├── tests/test_auditoria.py          # pytest: matriz de permisos, hash, BCP
├── pyproject.toml                   # configuración de ruff y pytest
└── requirements-dev.txt
```

## Qué aprendí

- A traducir cada principio CIA en **controles concretos** (RBAC, hashing, BCP) y no solo en definiciones.
- Que el control de acceso debe **denegar por defecto**: los tests encontraron que un recurso no listado se permitía, y lo corregí.
- Que un hash sin clave detecta cambios accidentales, pero contra un atacante con acceso hace falta un HMAC o una firma.
- A medir el impacto de la indisponibilidad en usuarios y tiempos de recuperación (RTO).
- A usar ruff (incluidas las reglas de seguridad `S`) y pytest para mantener el código revisable.

## Licencia

[MIT](LICENSE) © 2026 Fernandamv96
