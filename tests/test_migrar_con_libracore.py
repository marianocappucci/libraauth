"""`libraauth-migrar` contra la LibraCore real, cuando esta instalada.

Va en un archivo aparte y no en `test_cadena_alembic.py` a proposito: ese archivo
esta en el gate de PostgreSQL del CI, que falla ante **cualquier** skip, y
libraauth no depende de libracore, asi que en CI este test se saltea. Corre donde
libracore este instalada (un producto, o un venv local con `libracore>=1.103.0`).
"""

import pytest

from libraauth import migrar


def test_la_lista_por_defecto_es_la_de_libracore():
    """Sin inyectar nada, la lista de una sola base sale de LibraCore: los de una
    sola base caen al dominio, los de core aparte no."""
    ui = pytest.importorskip("libracore.db.url_de_instancia")
    if not hasattr(ui, "comparte_base_con_el_dominio"):
        pytest.skip("libracore anterior a v1.103.0")
    for prefijo in ("contalibra", "restolibra", "ventalibra", "libradesk"):
        assert migrar._comparte_base_segun_libracore(prefijo) is True
    for prefijo in ("gestiolibra", "medlibra", "libracargo", "libraclub"):
        assert migrar._comparte_base_segun_libracore(prefijo) is False
