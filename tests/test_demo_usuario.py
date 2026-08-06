"""`ensure_demo_user` — el usuario del auto-login de las demos publicas.

La ruta `POST /auth/demo` no sirve de nada sin un usuario al que entrar, y ese
usuario no puede aparecer en la base de un cliente. Las dos cosas se deciden
con **las mismas dos variables de entorno**, a proposito: si se decidieran por
separado existirian el par "ruta encendida sin usuario" y el par "usuario
suelto en la base de un cliente", que son las dos formas de que esto salga mal.

Lo que fijan estos tests, en orden de lo que se rompe sin que se note:

1. 🔴 **Que en una instancia normal no cree nada.** Un usuario de mas en la
   base de un cliente no rompe nada visible — y por eso nadie lo encuentra.
2. 🔴 **Que el rol sea `staff` y no salga del entorno.** Si saliera del
   entorno, un `.env` podria pedir admin.
3. 🔴 **Que NO le corrija el rol a un usuario que ya existe.** Corregirlo en
   silencio taparia el caso que el endpoint tiene que seguir rechazando.
4. Que la contrasena sea aleatoria y no se imprima.
"""
import pytest

from libraauth.bootstrap import ROL_DEMO, ensure_demo_user


class _Repo:
    """Repositorio en memoria con la superficie que usa `ensure_demo_user`."""

    def __init__(self, usuarios=None):
        self.usuarios = dict(usuarios or {})
        self.creados = []

    def get_by_username(self, username):
        return self.usuarios.get(username)

    def create(self, *, username, name, password, role, email=""):
        u = {"id": str(len(self.usuarios) + 1), "username": username, "name": name,
             "role": role, "active": True, "_password": password}
        self.usuarios[username] = u
        self.creados.append(u)
        return u


@pytest.fixture
def demo_encendida(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.setenv("DEMO_USERNAME", "visitante")


# ── 🔴 En una instancia normal, nada ──────────────────────────────────────

def test_sin_las_variables_no_crea_nada(monkeypatch):
    """Un usuario de mas en la base de un cliente no rompe nada visible, y por
    eso nadie lo encontraria."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.delenv("DEMO_USERNAME", raising=False)
    repo = _Repo()

    assert ensure_demo_user(repo) is None
    assert repo.creados == []


def test_con_DEMO_MODE_pero_sin_usuario_no_crea_nada(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    monkeypatch.delenv("DEMO_USERNAME", raising=False)
    repo = _Repo()

    assert ensure_demo_user(repo) is None
    assert repo.creados == []


def test_con_usuario_pero_sin_DEMO_MODE_no_crea_nada(monkeypatch):
    """🔴 El caso que de verdad importa: alguien pone `DEMO_USERNAME` en el
    `.env` de un cliente al copiarlo de la demo, pero no `DEMO_MODE`."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.setenv("DEMO_USERNAME", "visitante")
    repo = _Repo()

    assert ensure_demo_user(repo) is None
    assert repo.creados == []


# ── En una demo, el usuario correcto ──────────────────────────────────────

def test_en_una_demo_crea_el_usuario(demo_encendida):
    repo = _Repo()

    assert ensure_demo_user(repo) == "visitante"
    assert [u["username"] for u in repo.creados] == ["visitante"]


def test_el_rol_es_staff_y_no_sale_del_entorno(demo_encendida, monkeypatch):
    """🔴 Si saliera del entorno, un `.env` podria pedir admin."""
    monkeypatch.setenv("DEMO_ROLE", "admin")
    monkeypatch.setenv("ROL_DEMO", "admin")
    repo = _Repo()
    ensure_demo_user(repo)

    assert repo.creados[0]["role"] == "staff"
    assert ROL_DEMO == "staff"


def test_la_contrasena_es_larga_y_aleatoria(demo_encendida):
    """Al usuario de la demo se entra por `POST /auth/demo`, no tipeando la
    contrasena — pero el login normal sigue existiendo, asi que tiene que ser
    inadivinable igual."""
    uno, otro = _Repo(), _Repo()
    ensure_demo_user(uno)
    ensure_demo_user(otro)

    clave = uno.creados[0]["_password"]
    assert len(clave) >= 24
    assert clave != otro.creados[0]["_password"]


def test_no_imprime_la_contrasena(demo_encendida, capsys):
    """A diferencia de `ensure_admin_user`, que la deja en los logs del
    contenedor. Acá no hace falta que nadie la lea."""
    repo = _Repo()
    ensure_demo_user(repo)

    salida = capsys.readouterr().out
    assert repo.creados[0]["_password"] not in salida
    assert "visitante" in salida


# ── 🔴 Idempotente, y sin corregir por atras ──────────────────────────────

def test_correrlo_dos_veces_no_duplica(demo_encendida):
    repo = _Repo()
    ensure_demo_user(repo)
    ensure_demo_user(repo)

    assert len(repo.creados) == 1


def test_no_le_corrige_el_rol_a_un_usuario_que_ya_existe(demo_encendida):
    """🔴 Si alguien promovio al usuario de la demo a admin desde el ABM,
    corregirlo acá en silencio taparia el caso que `POST /auth/demo` tiene que
    seguir rechazando. Se quiere ruidoso, no arreglado por atras."""
    repo = _Repo({"visitante": {"username": "visitante", "role": "admin", "active": True}})

    assert ensure_demo_user(repo) == "visitante"
    assert repo.creados == []
    assert repo.usuarios["visitante"]["role"] == "admin"
