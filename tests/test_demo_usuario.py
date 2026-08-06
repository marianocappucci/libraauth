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

    def update_password(self, user_id, new_password):
        # Busca **por id**, como el repositorio real. Si el codigo le pasara el
        # username —que es el error facil, porque este dict esta indexado
        # asi— esto revienta en vez de "funcionar" contra una clave
        # equivocada.
        for u in self.usuarios.values():
            if u["id"] == user_id:
                u["_password"] = new_password
                return
        raise AssertionError(f"update_password con un id inexistente: {user_id!r}")


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


# ── 🔴 El rol lo elige el producto, y se valida ───────────────────────────

class _RepoConRoles(_Repo):
    """Como el de Contalibra: `("admin", "operador", "cajero")`. **No tiene
    `staff`** — que era el default fijo del motor hasta el 2026-08-06."""

    roles = ("admin", "operador", "cajero")


def test_un_producto_con_otro_vocabulario_pasa_su_rol(demo_encendida):
    repo = _RepoConRoles()

    assert ensure_demo_user(repo, rol="operador") == "visitante"
    assert repo.creados[0]["role"] == "operador"


def test_un_rol_que_el_producto_no_conoce_corta_el_arranque(demo_encendida):
    """🔴 Ruidoso a propósito. Con el `staff` fijo, en Contalibra el alta moría
    con `ValueError: invalid role: 'staff'` desde adentro del repositorio; el
    mensaje no decía qué hacer. Y si en cambio se hubiera tragado el error, la
    instancia habría quedado sin usuario de demo y el 503 habría aparecido
    recién cuando alguien tocara el botón."""
    with pytest.raises(RuntimeError, match="no existe en este producto"):
        ensure_demo_user(_RepoConRoles())


def test_el_mensaje_nombra_los_roles_validos(demo_encendida):
    """Sin eso hay que ir a buscar el vocabulario al código del producto."""
    with pytest.raises(RuntimeError) as e:
        ensure_demo_user(_RepoConRoles())

    assert "operador" in str(e.value)
    assert "cajero" in str(e.value)


def test_pedir_un_rol_prohibido_corta_el_arranque(demo_encendida):
    """La otra mitad: pedir admin explícitamente tampoco pasa."""
    with pytest.raises(RuntimeError, match="ROLES_PROHIBIDOS_EN_DEMO"):
        ensure_demo_user(_RepoConRoles(), rol="admin")


def test_el_rol_se_valida_aunque_el_usuario_ya_exista(demo_encendida):
    """La validación va **antes** del corte por idempotencia. Si fuera después,
    una instancia mal configurada arrancaría en silencio a partir del segundo
    arranque y el error se volvería intermitente."""
    repo = _RepoConRoles({"visitante": {"username": "visitante", "role": "operador",
                                        "active": True}})

    with pytest.raises(RuntimeError, match="no existe en este producto"):
        ensure_demo_user(repo)


def test_no_le_corrige_el_rol_a_un_usuario_que_ya_existe(demo_encendida):
    """🔴 Si alguien promovio al usuario de la demo a admin desde el ABM,
    corregirlo acá en silencio taparia el caso que `POST /auth/demo` tiene que
    seguir rechazando. Se quiere ruidoso, no arreglado por atras."""
    repo = _Repo({"visitante": {"username": "visitante", "role": "admin", "active": True}})

    assert ensure_demo_user(repo) == "visitante"
    assert repo.creados == []
    assert repo.usuarios["visitante"]["role"] == "admin"


# ── La contrasena tipeable (`DEMO_PASSWORD`, 2026-08-06) ──────────────────
#
# Pedido del negocio: poder decirle a un cliente potencial "entra a
# demo.<producto>.com.ar con usuario demo y contrasena demo". El boton de
# auto-login cubre a quien llega solo por la landing; esto cubre a quien
# recibe el dato por telefono.

def test_con_DEMO_PASSWORD_el_usuario_nuevo_la_usa(demo_encendida, monkeypatch):
    monkeypatch.setenv("DEMO_PASSWORD", "demo")
    repo = _Repo()
    ensure_demo_user(repo)

    assert repo.creados[0]["_password"] == "demo"


def test_le_reescribe_la_contrasena_a_un_usuario_que_ya_existe(demo_encendida, monkeypatch):
    """🔴 El caso real de las seis demos: el usuario ya estaba creado con una
    contrasena aleatoria cuando se decidio que tenia que ser tipeable. Sin
    esto, cambiar `DEMO_PASSWORD` en el `.env` no haria nada sobre una
    instancia ya sembrada y el dato que se le pasa al cliente seria falso —
    sin ningun error que lo delate."""
    repo = _Repo({"visitante": {"id": "7", "username": "visitante", "role": "staff",
                                "active": True, "_password": "aleatoria-vieja"}})
    monkeypatch.setenv("DEMO_PASSWORD", "demo")

    assert ensure_demo_user(repo) == "visitante"
    assert repo.usuarios["visitante"]["_password"] == "demo"
    assert repo.creados == []


def test_sin_DEMO_PASSWORD_no_le_toca_la_contrasena_al_que_ya_existe(demo_encendida):
    """La idempotencia de siempre: sin contrasena declarada no hay nada que
    converger, y reescribirla con una aleatoria nueva en cada arranque dejaria
    fuera a cualquiera que ya estuviera adentro."""
    repo = _Repo({"visitante": {"id": "7", "username": "visitante", "role": "staff",
                                "active": True, "_password": "aleatoria-vieja"}})

    ensure_demo_user(repo)

    assert repo.usuarios["visitante"]["_password"] == "aleatoria-vieja"


def test_DEMO_PASSWORD_sin_DEMO_MODE_no_crea_ni_toca_nada(monkeypatch):
    """🔴 El mismo cerrojo que las otras dos variables. Es el caso de copiar el
    `.env` de la demo a la instancia de un cliente: sin `DEMO_MODE` la
    contrasena debil no llega a ningun usuario."""
    monkeypatch.delenv("DEMO_MODE", raising=False)
    monkeypatch.setenv("DEMO_USERNAME", "visitante")
    monkeypatch.setenv("DEMO_PASSWORD", "demo")
    repo = _Repo({"visitante": {"id": "7", "username": "visitante", "role": "staff",
                                "active": True, "_password": "aleatoria-vieja"}})

    assert ensure_demo_user(repo) is None
    assert repo.usuarios["visitante"]["_password"] == "aleatoria-vieja"


def test_una_contrasena_conocida_sobre_un_admin_corta_el_arranque(demo_encendida, monkeypatch):
    """🔴 El agujero que abre esta feature si no se lo tapa: `POST /auth/demo`
    se niega a entregar admin, pero **el login normal no tiene ese cerrojo**.
    Un usuario de demo promovido a admin desde el ABM + una contrasena que
    esta publicada = cualquiera entra como admin. Se corta el arranque, que es
    la unica forma de que alguien se entere."""
    repo = _Repo({"visitante": {"id": "7", "username": "visitante", "role": "admin",
                                "active": True, "_password": "aleatoria-vieja"}})
    monkeypatch.setenv("DEMO_PASSWORD", "demo")

    with pytest.raises(RuntimeError, match="ROLES_PROHIBIDOS_EN_DEMO"):
        ensure_demo_user(repo)

    assert repo.usuarios["visitante"]["_password"] == "aleatoria-vieja"
