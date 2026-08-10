"""El `ts` de un log llega como texto o como datetime, según el motor.

Por qué existe: el modelo declara `ts` como `DateTime`, pero en los productos
que crean la tabla con **DDL crudo** la columna es `TEXT` — en esta familia los
timestamps de la capa cruda son texto a propósito, porque las fechas se filtran
comparando lexicográficamente.

Contra SQLite el desacuerdo no se ve (el dialecto parsea el texto y devuelve un
`datetime`); contra PostgreSQL llega el `str` crudo. Medido en [[ventalibra]] el
2026-08-10: **19 apariciones** de *'str' object has no attribute 'strftime'*.
"""
from datetime import datetime

from libraauth.auditoria import ts_legible


def test_un_datetime_sale_con_el_formato_de_siempre():
    assert ts_legible(datetime(2026, 8, 10, 3, 4, 5)) == "2026-08-10 03:04:05"


def test_un_texto_sale_igual_que_entro():
    """El que llega desde una columna TEXT ya viene con ese formato: la capa
    cruda lo escribe así y la pantalla de logs lo parte así."""
    assert ts_legible("2026-08-10 03:04:05") == "2026-08-10 03:04:05"


def test_los_dos_caminos_dan_EXACTAMENTE_lo_mismo():
    """Lo que importa no es que ninguno rompa: es que den el mismo texto.

    Si difirieran, la pantalla de logs se vería distinta según el motor y nadie
    lo notaría hasta comparar dos instancias.
    """
    momento = datetime(2026, 8, 10, 3, 4, 5)
    assert ts_legible(momento) == ts_legible("2026-08-10 03:04:05")


def test_vacio_y_nulo_no_rompen():
    assert ts_legible(None) == ""
    assert ts_legible("") == ""
