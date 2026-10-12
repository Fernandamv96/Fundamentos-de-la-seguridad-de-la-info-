import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import auditoria_seguridad_inacap as aud

# --- Confidencialidad ----------------------------------------------------------


@pytest.fixture
def control():
    return aud.ControlDeAcceso()


@pytest.mark.parametrize(
    ("usuario", "rol", "recurso", "objetivo", "esperado"),
    [
        ("12345678-9", "alumno", "notas_propias", "12345678-9", True),
        ("12345678-9", "alumno", "notas_propias", "98765432-1", False),
        ("12345678-9", "alumno", "fuas_ajeno", "98765432-1", False),
        ("12345678-9", "alumno", "datos_sensibles_ajenos", "98765432-1", False),
        ("DOC999", "docente", "datos_sensibles_ajenos", "12345678-9", False),
        ("ADM001", "administrativo", "datos_sensibles_ajenos", "12345678-9", True),
        ("AUD001", "auditor", "fuas_ajeno", "12345678-9", True),
        ("X", "rol_inventado", "notas_propias", "X", False),
    ],
)
def test_matriz_de_permisos(control, usuario, rol, recurso, objetivo, esperado):
    assert control.solicitar_acceso(usuario, rol, recurso, objetivo) is esperado


def test_recurso_desconocido_se_deniega_aunque_sea_el_propio_rut(control):
    # Regresión: antes un alumno obtenía acceso a cualquier recurso no listado.
    assert control.solicitar_acceso("12345678-9", "alumno", "panel_admin", "12345678-9") is False


def test_cada_intento_queda_en_el_log(control):
    control.solicitar_acceso("12345678-9", "alumno", "fuas_ajeno", "98765432-1")
    control.solicitar_acceso("ADM001", "administrativo", "fuas_ajeno", "12345678-9")
    assert [e["permitido"] for e in control.log_accesos] == [False, True]
    assert all(e["ip_simulada"].startswith("192.168.1.") for e in control.log_accesos)


# --- Integridad ----------------------------------------------------------------


@pytest.fixture
def sistema():
    s = aud.SistemaIntegridad()
    s.registrar_alumno("12345678-9", nota_1=3.5, nota_2=4.0, asistencia_pct=60.0)
    return s


def test_cambio_no_autorizado_se_revierte(sistema):
    sistema.modificar_nota("12345678-9", "nota_1", 7.0, editor="alumno", autorizado=False)
    assert sistema.registros["12345678-9"]["datos"]["nota_1"] == 3.5
    assert sistema.verificar_integridad("12345678-9") is True
    assert sistema.historial[-1]["autorizado"] is False


def test_cambio_autorizado_actualiza_hash(sistema):
    hash_antes = sistema.registros["12345678-9"]["hash_guardado"]
    sistema.modificar_nota("12345678-9", "nota_2", 4.5, editor="docente", autorizado=True)
    registro = sistema.registros["12345678-9"]
    assert registro["datos"]["nota_2"] == 4.5
    assert registro["hash_guardado"] != hash_antes
    assert sistema.verificar_integridad("12345678-9") is True


def test_manipulacion_directa_se_detecta_por_hash(sistema):
    # Simula un cambio hecho por fuera del sistema (p. ej. directo en la BD)
    sistema.registros["12345678-9"]["datos"]["asistencia_pct"] = 100.0
    assert sistema.verificar_integridad("12345678-9") is False


def test_campo_inexistente_no_rompe_ni_modifica(sistema):
    # Regresión: antes lanzaba KeyError al revertir
    datos_antes = dict(sistema.registros["12345678-9"]["datos"])
    sistema.modificar_nota("12345678-9", "nota_99", 7.0, editor="x", autorizado=False)
    assert sistema.registros["12345678-9"]["datos"] == datos_antes
    assert sistema.historial == []


# --- Disponibilidad ------------------------------------------------------------


def test_ataque_y_plan_de_continuidad(monkeypatch):
    monkeypatch.setattr(aud.time, "sleep", lambda _s: None)
    sd = aud.SimuladorDisponibilidad()

    sd.simular_ataque("DDoS")
    assert not any(sd.estado_servicios.values())
    assert sd.incidentes[-1]["afectados"] == 45_000 + 38_000 + 52_000

    sd.activar_plan_continuidad()
    assert all(sd.estado_servicios.values())
    assert sd.incidentes[-1]["resuelto"] is True


def test_main_corre_completo(monkeypatch, capsys):
    monkeypatch.setattr(aud.time, "sleep", lambda _s: None)
    aud.main()
    salida = capsys.readouterr().out
    assert "Simulación completada" in salida
