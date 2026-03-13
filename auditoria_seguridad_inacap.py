"""
=============================================================================
AUDITORÍA DE SEGURIDAD - INTRANET Y SISTEMAS INACAP
Principios CIA: Confidencialidad, Integridad, Disponibilidad
=============================================================================
Autor     : Auditoría de Seguridad Informática
Contexto  : Simulación de controles de seguridad para los sistemas INACAP
            (Intranet, INACAPMail, LMS Moodle)
=============================================================================
"""

import hashlib
import datetime
import random
import time
from typing import Optional

# ============================================================
# MÓDULO 1 — CONFIDENCIALIDAD
# Control de acceso a datos sensibles de alumnos
# (enfermedades preexistentes, ingresos familiares, FUAS)
# ============================================================

class ControlDeAcceso:
    """
    Simula controles de confidencialidad para evitar que compañeros
    accedan a información sensible de otros alumnos.
    """

    # Roles y sus permisos sobre datos sensibles
    PERMISOS = {
        "alumno":       {"notas_propias": True,  "datos_sensibles_ajenos": False, "fuas_ajeno": False},
        "docente":      {"notas_propias": False,  "datos_sensibles_ajenos": False, "fuas_ajeno": False},
        "administrativo": {"notas_propias": False, "datos_sensibles_ajenos": True,  "fuas_ajeno": True},
        "auditor":      {"notas_propias": False,  "datos_sensibles_ajenos": True,  "fuas_ajeno": True},
    }

    def __init__(self):
        # Registro de accesos (log de auditoría)
        self.log_accesos: list[dict] = []

    def _registrar_evento(self, usuario: str, rol: str, recurso: str,
                          rut_objetivo: str, permitido: bool) -> None:
        """Registra cada intento de acceso para auditoría posterior."""
        evento = {
            "timestamp":    datetime.datetime.now().isoformat(),
            "usuario":      usuario,
            "rol":          rol,
            "recurso":      recurso,
            "rut_objetivo": rut_objetivo,
            "permitido":    permitido,
            "ip_simulada":  f"192.168.1.{random.randint(2, 254)}",
        }
        self.log_accesos.append(evento)

    def solicitar_acceso(self, usuario: str, rol: str,
                         recurso: str, rut_objetivo: str) -> bool:
        """
        Evalúa si el usuario tiene permiso para acceder al recurso solicitado.

        Controles implementados:
        - RBAC (Control de Acceso Basado en Roles)
        - Separación de datos por RUT (un alumno no ve datos de otro)
        - Registro de auditoría en cada intento
        """
        if rol not in self.PERMISOS:
            permitido = False
        else:
            permisos_rol = self.PERMISOS[rol]

            # Un alumno solo puede ver SUS PROPIOS datos básicos
            if rol == "alumno":
                if recurso in ("datos_sensibles_ajenos", "fuas_ajeno"):
                    permitido = False
                else:
                    # Verifica que el alumno acceda a sus propios datos
                    permitido = (usuario == rut_objetivo)
            else:
                permitido = permisos_rol.get(recurso, False)

        self._registrar_evento(usuario, rol, recurso, rut_objetivo, permitido)
        return permitido

    def mostrar_log(self) -> None:
        """Imprime el registro de accesos para revisión."""
        print("\n" + "=" * 60)
        print("  LOG DE AUDITORÍA — CONTROL DE ACCESO")
        print("=" * 60)
        for entrada in self.log_accesos:
            estado = "✅ PERMITIDO" if entrada["permitido"] else "🚫 DENEGADO"
            print(f"[{entrada['timestamp']}] {estado}")
            print(f"  Usuario : {entrada['usuario']} ({entrada['rol']})")
            print(f"  Recurso : {entrada['recurso']}  |  Objetivo: {entrada['rut_objetivo']}")
            print(f"  IP      : {entrada['ip_simulada']}")
            print("-" * 60)


# ============================================================
# MÓDULO 2 — INTEGRIDAD
# Detección de modificación no autorizada de notas/asistencia
# ============================================================

class SistemaIntegridad:
    """
    Simula mecanismos para detectar y prevenir alteraciones
    de notas o asistencia a nivel de red o interno.

    Técnicas:
    - Hash SHA-256 de los registros académicos
    - Registro de cambios con autor y timestamp
    - Alerta ante discrepancias de hash
    """

    def __init__(self):
        self.registros: dict[str, dict] = {}   # rut → datos académicos
        self.historial: list[dict] = []        # historial de modificaciones

    def _calcular_hash(self, datos: dict) -> str:
        """Genera un hash SHA-256 determinista del registro académico."""
        contenido = str(sorted(datos.items())).encode("utf-8")
        return hashlib.sha256(contenido).hexdigest()

    def registrar_alumno(self, rut: str, nota_1: float,
                         nota_2: float, asistencia_pct: float) -> None:
        """Crea el registro inicial con su hash de integridad."""
        datos = {
            "rut":            rut,
            "nota_1":         nota_1,
            "nota_2":         nota_2,
            "asistencia_pct": asistencia_pct,
        }
        hash_inicial = self._calcular_hash(datos)
        self.registros[rut] = {
            "datos":          datos,
            "hash_guardado":  hash_inicial,
            "ultima_edicion": datetime.datetime.now().isoformat(),
            "editor":         "sistema",
        }
        print(f"[INTEGRIDAD] Registro creado para RUT {rut}  |  Hash: {hash_inicial[:20]}...")

    def modificar_nota(self, rut: str, campo: str,
                       nuevo_valor: float, editor: str, autorizado: bool) -> None:
        """
        Simula un intento de modificación (autorizado o no).
        Si no está autorizado, el sistema detecta la anomalía.
        """
        if rut not in self.registros:
            print(f"[ERROR] RUT {rut} no encontrado.")
            return

        registro = self.registros[rut]
        datos_anteriores = registro["datos"].copy()

        # Aplicar el cambio
        registro["datos"][campo] = nuevo_valor
        hash_nuevo = self._calcular_hash(registro["datos"])

        evento = {
            "timestamp":        datetime.datetime.now().isoformat(),
            "rut":              rut,
            "campo_modificado": campo,
            "valor_anterior":   datos_anteriores.get(campo),
            "valor_nuevo":      nuevo_valor,
            "editor":           editor,
            "autorizado":       autorizado,
            "hash_antes":       registro["hash_guardado"],
            "hash_despues":     hash_nuevo,
        }
        self.historial.append(evento)

        if not autorizado:
            # 🚨 ALERTA: modificación detectada sin autorización
            print(f"\n🚨 [ALERTA INTEGRIDAD] Modificación NO AUTORIZADA detectada.")
            print(f"   RUT     : {rut}")
            print(f"   Campo   : {campo}  |  {datos_anteriores.get(campo)} → {nuevo_valor}")
            print(f"   Editor  : {editor}")
            print(f"   Acción  : Cambio REVERTIDO. Notificación enviada al área de seguridad.")
            # Revertir el cambio
            registro["datos"][campo] = datos_anteriores[campo]
        else:
            # Actualizar hash legítimo
            registro["hash_guardado"]  = hash_nuevo
            registro["ultima_edicion"] = datetime.datetime.now().isoformat()
            registro["editor"]         = editor
            print(f"[INTEGRIDAD] Modificación AUTORIZADA aceptada para {rut}.")

    def verificar_integridad(self, rut: str) -> bool:
        """Recalcula el hash y lo compara con el almacenado."""
        registro = self.registros.get(rut)
        if not registro:
            return False
        hash_actual = self._calcular_hash(registro["datos"])
        integro     = (hash_actual == registro["hash_guardado"])
        estado = "✅ ÍNTEGRO" if integro else "🚨 COMPROMETIDO"
        print(f"[VERIFICACIÓN] RUT {rut}: {estado}")
        return integro

    def mostrar_historial(self) -> None:
        print("\n" + "=" * 60)
        print("  HISTORIAL DE MODIFICACIONES ACADÉMICAS")
        print("=" * 60)
        for e in self.historial:
            marca = "🟢" if e["autorizado"] else "🔴"
            print(f"{marca} [{e['timestamp']}] {e['rut']} — {e['campo_modificado']}: "
                  f"{e['valor_anterior']} → {e['valor_nuevo']}  (por: {e['editor']})")


# ============================================================
# MÓDULO 3 — DISPONIBILIDAD
# Simulación de ataque DoS en semana de exámenes y plan de respuesta
# ============================================================

class SimuladorDisponibilidad:
    """
    Simula el impacto de un ataque que deja inoperativos:
    - INACAPMail
    - LMS (Moodle)
    - Intranet

    Incluye un plan de respuesta y métricas de impacto.
    """

    SERVICIOS = {
        "INACAPMail": {"usuarios_activos": 45_000, "critico": True},
        "LMS_Moodle": {"usuarios_activos": 38_000, "critico": True},
        "Intranet":   {"usuarios_activos": 52_000, "critico": True},
    }

    def __init__(self):
        self.estado_servicios: dict[str, bool] = {s: True for s in self.SERVICIOS}
        self.incidentes: list[dict] = []

    def simular_ataque(self, tipo: str = "DDoS") -> None:
        """Simula un ataque de disponibilidad durante semana de exámenes."""
        print("\n" + "=" * 60)
        print(f"  🔴 SIMULACIÓN DE ATAQUE: {tipo}")
        print(f"  Fecha simulada: SEMANA DE EXÁMENES FINALES")
        print("=" * 60)

        total_afectados = 0
        for servicio, info in self.SERVICIOS.items():
            self.estado_servicios[servicio] = False
            total_afectados += info["usuarios_activos"]
            print(f"  ❌ {servicio} — CAÍDO  ({info['usuarios_activos']:,} usuarios afectados)")

        print(f"\n  ⚠️  Total usuarios impactados: {total_afectados:,}")
        print("\n  IMPACTO ESTIMADO:")
        print("  • Alumnos sin acceso a guías, evaluaciones y foros en Moodle")
        print("  • Comunicaciones institucionales interrumpidas (INACAPMail)")
        print("  • Imposibilidad de revisar horarios, notas y trámites (Intranet)")
        print("  • Daño reputacional: cobertura en redes sociales y medios")
        print("  • Riesgo legal: incumplimiento del deber de continuidad educativa")

        incidente = {
            "timestamp":    datetime.datetime.now().isoformat(),
            "tipo_ataque":  tipo,
            "servicios":    list(self.SERVICIOS.keys()),
            "afectados":    total_afectados,
            "resuelto":     False,
        }
        self.incidentes.append(incidente)

    def activar_plan_continuidad(self) -> None:
        """Ejecuta el plan de continuidad operacional (BCP)."""
        print("\n" + "=" * 60)
        print("  🛡️  PLAN DE CONTINUIDAD OPERACIONAL ACTIVADO")
        print("=" * 60)

        pasos = [
            ("00:00", "Detección automática del ataque vía SIEM / IDS"),
            ("00:05", "Notificación al equipo de respuesta a incidentes (CSIRT)"),
            ("00:10", "Activación de servidores de respaldo en nube (failover)"),
            ("00:15", "Redirección de tráfico a CDN con protección anti-DDoS (Cloudflare/Akamai)"),
            ("00:30", "Servicios críticos restaurados en modo degradado"),
            ("01:00", "Comunicado oficial enviado a alumnos y docentes"),
            ("02:00", "Servicios completamente restaurados"),
            ("24:00", "Informe post-incidente y mejoras implementadas"),
        ]

        for tiempo, accion in pasos:
            print(f"  +{tiempo} h → {accion}")
            time.sleep(0.1)   # pausa visual de simulación

        # Restaurar servicios
        for servicio in self.estado_servicios:
            self.estado_servicios[servicio] = True

        print("\n  ✅ Todos los servicios han sido RESTAURADOS.")
        if self.incidentes:
            self.incidentes[-1]["resuelto"] = True

    def mostrar_estado(self) -> None:
        print("\n  ESTADO ACTUAL DE SERVICIOS:")
        for servicio, activo in self.estado_servicios.items():
            icono = "🟢 ACTIVO" if activo else "🔴 CAÍDO"
            print(f"  {icono}  — {servicio}")


# ============================================================
# PROGRAMA PRINCIPAL — DEMOSTRACIÓN COMPLETA
# ============================================================

def separador(titulo: str) -> None:
    print("\n" + "█" * 60)
    print(f"  {titulo}")
    print("█" * 60)


def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║   AUDITORÍA DE SEGURIDAD — SISTEMAS INACAP               ║
║   Principios CIA: Confidencialidad · Integridad ·        ║
║                   Disponibilidad                         ║
╚══════════════════════════════════════════════════════════╝
    """)

    # ----------------------------------------------------------
    # 1. CONFIDENCIALIDAD
    # ----------------------------------------------------------
    separador("1. CONFIDENCIALIDAD — Control de Acceso a Datos Sensibles")

    control = ControlDeAcceso()

    # Alumno intenta ver FUAS de otro alumno → DENEGADO
    control.solicitar_acceso("12345678-9", "alumno", "fuas_ajeno", "98765432-1")

    # Alumno accede a sus propias notas → PERMITIDO
    control.solicitar_acceso("12345678-9", "alumno", "notas_propias", "12345678-9")

    # Administrativo accede a datos sensibles → PERMITIDO
    control.solicitar_acceso("ADM001", "administrativo", "datos_sensibles_ajenos", "12345678-9")

    # Docente intenta ver datos sensibles → DENEGADO
    control.solicitar_acceso("DOC999", "docente", "datos_sensibles_ajenos", "12345678-9")

    control.mostrar_log()

    print("""
  CONTROLES PROPUESTOS:
  • RBAC: roles definidos con permisos mínimos necesarios
  • Cifrado AES-256 para datos en reposo (FUAS, salud, ingresos)
  • TLS 1.3 para datos en tránsito
  • MFA obligatorio para acceso a información sensible
  • Auditoría de accesos con alertas automáticas ante accesos anómalos
    """)

    # ----------------------------------------------------------
    # 2. INTEGRIDAD
    # ----------------------------------------------------------
    separador("2. INTEGRIDAD — Detección de Alteración de Notas/Asistencia")

    si = SistemaIntegridad()
    si.registrar_alumno("12345678-9", nota_1=3.5, nota_2=4.0, asistencia_pct=60.0)

    # Modificación autorizada por docente
    si.modificar_nota("12345678-9", "nota_2", 4.5, editor="docente_DOC001", autorizado=True)

    # Alumno intenta cambiar su nota (interceptación de red simulada)
    si.modificar_nota("12345678-9", "nota_1", 7.0, editor="alumno_12345678-9", autorizado=False)

    # Verificación de integridad
    si.verificar_integridad("12345678-9")
    si.mostrar_historial()

    print("""
  CONTROLES PROPUESTOS:
  • Firma digital (HMAC / SHA-256) en cada registro académico
  • Protocolo HTTPS + certificados válidos (evita MITM)
  • Registro inmutable de cambios con autor y timestamp
  • Separación de roles: solo docentes autorizados pueden editar notas
  • Alertas en tiempo real ante modificaciones fuera de horario o rango
    """)

    # ----------------------------------------------------------
    # 3. DISPONIBILIDAD
    # ----------------------------------------------------------
    separador("3. DISPONIBILIDAD — Simulación de Ataque en Semana de Exámenes")

    sd = SimuladorDisponibilidad()
    sd.mostrar_estado()
    sd.simular_ataque(tipo="DDoS volumétrico")
    sd.activar_plan_continuidad()
    sd.mostrar_estado()

    print("""
  CONTROLES PROPUESTOS:
  • Protección anti-DDoS con Cloudflare / Akamai
  • Balanceo de carga y servidores de respaldo (failover automático)
  • Plan de Continuidad del Negocio (BCP) con RTO < 2 horas
  • Comunicación proactiva a alumnos y docentes ante incidentes
  • Calendario de mantenimiento fuera de períodos críticos
  • Monitoreo 24/7 con SIEM e IDS/IPS
    """)

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  Simulación completada. Principios CIA evaluados.        ║")
    print("╚══════════════════════════════════════════════════════════╝\n")


if __name__ == "__main__":
    main()
