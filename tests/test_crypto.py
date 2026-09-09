"""Tests del cifrado en reposo (v0.6.0).

Lo que estos tests fijan no es "que ande el AES" —eso lo garantiza la
biblioteca— sino las decisiones propias: que la clave se DERIVE y no se reuse,
que cifrar dos veces lo mismo de valores distintos, que un secreto vacio no
genere un blob que parezca un valor cargado, y que rotar el SECRET_KEY se
manifieste como `SecretoIndescifrable` y no como basura silenciosa.
"""
import base64

import pytest

from libraauth import crypto
from libraauth.crypto import (
    ClaveDeCifradoAusente,
    SecretoIndescifrable,
    cifrar,
    clave_de_cifrado,
    descifrar,
)


@pytest.fixture(autouse=True)
def _entorno_limpio(monkeypatch):
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    # Sin esto, una `LIBRAAUTH_CLAVES_ANTERIORES` que exista en la maquina
    # donde corre la suite le daria a `descifrar` una clave de mas: los tests
    # de rotacion pasarian o fallarian segun el entorno, que es la peor forma
    # de fallar.
    monkeypatch.delenv(crypto.CLAVES_ANTERIORES, raising=False)
    monkeypatch.setenv("SECRET_KEY", "a" * 64)


def test_ida_y_vuelta():
    assert descifrar(cifrar("clave-smtp-real")) == "clave-smtp-real"


def test_el_texto_original_no_aparece_en_el_blob():
    """Lo minimo que tiene que cumplir: quien abra la base con un visor de
    SQLite no puede leer la contrasena."""
    blob = cifrar("hunter2")
    assert "hunter2" not in blob
    assert b"hunter2" not in base64.b64decode(blob[len("v1:"):])


def test_cifrar_dos_veces_lo_mismo_da_valores_distintos():
    """El nonce es aleatorio. Sin esto, comparar dos bases revelaria que dos
    instancias comparten la misma contrasena SMTP."""
    assert cifrar("misma") != cifrar("misma")
    assert descifrar(cifrar("misma")) == "misma"


def test_vacio_se_guarda_vacio():
    """Cifrar "" daria un blob que parece un valor cargado, y habria que
    descifrarlo para descubrir que no habia nada."""
    assert cifrar("") == ""
    assert descifrar("") == ""


def test_la_clave_se_deriva_no_es_el_secret_key(monkeypatch):
    """La clave de cifrado tiene que ser DISTINTA del secreto que firma la
    cookie de sesion, aunque salga de el."""
    monkeypatch.setenv("SECRET_KEY", "b" * 64)
    derivada = clave_de_cifrado()
    assert derivada != ("b" * 64).encode()
    assert derivada != ("b" * 64).encode()[:32]
    assert len(derivada) == 32


def test_la_derivacion_es_estable_entre_llamadas():
    """Si no, lo cifrado en un arranque no se podria leer en el siguiente."""
    assert clave_de_cifrado() == clave_de_cifrado()


def test_encryption_key_explicita_tiene_prioridad(monkeypatch):
    monkeypatch.setenv("LIBRAAUTH_ENCRYPTION_KEY", "clave-dedicada")
    con_dedicada = clave_de_cifrado()
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY")
    assert clave_de_cifrado() != con_dedicada


def test_rotar_el_secret_key_sin_declarar_el_anterior_da_secreto_indescifrable(
    monkeypatch,
):
    """El caso realista de fallo. Importa que se distinga de "no hay nada
    guardado": son dos situaciones distintas para el humano que lo mira."""
    blob = cifrar("clave-vieja")
    monkeypatch.setenv("SECRET_KEY", "z" * 64)
    with pytest.raises(SecretoIndescifrable):
        descifrar(blob)


def test_blob_manipulado_no_se_descifra_en_silencio():
    """AES-GCM es autenticado: un byte cambiado invalida el tag en vez de
    devolver texto corrupto."""
    blob = cifrar("clave-smtp")
    crudo = bytearray(base64.b64decode(blob[len("v1:"):]))
    crudo[-1] ^= 0x01
    manipulado = "v1:" + base64.b64encode(bytes(crudo)).decode()
    with pytest.raises(SecretoIndescifrable):
        descifrar(manipulado)


def test_valor_sin_prefijo_de_version_se_rechaza():
    """Protege del caso en que alguien haya escrito la contrasena en claro
    directamente en la columna: se rechaza en vez de usarse."""
    with pytest.raises(SecretoIndescifrable):
        descifrar("contrasena-en-claro")


def test_valor_truncado_se_rechaza():
    with pytest.raises(SecretoIndescifrable):
        descifrar("v1:" + base64.b64encode(b"corto").decode())


def test_base64_invalido_se_rechaza():
    with pytest.raises(SecretoIndescifrable):
        descifrar("v1:no-es-base64!!!")


def test_sin_ningun_secreto_en_el_entorno_falla_al_cifrar(monkeypatch):
    """Fail-closed: antes que guardar en claro "porque no habia clave",
    lanza. Con `ENV` sin declarar el default es `production`."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("ENV", raising=False)
    with pytest.raises(ClaveDeCifradoAusente):
        cifrar("algo")


def test_en_desarrollo_sin_secret_key_hay_fallback(monkeypatch):
    """Misma convencion que `session_auth._resolve_secret_key`.

    Sin esto, cualquier entorno local o suite que no exporte `SECRET_KEY`
    —que es el caso de los 6 productos, que corren con `ENV=development`—
    recibe un 500 al guardar la config SMTP. Se encontro adoptando la v0.6.0
    en Gestiolibra.
    """
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("ENV", "development")

    assert descifrar(cifrar("clave-de-dev")) == "clave-de-dev"


def test_el_fallback_de_dev_no_aplica_en_produccion(monkeypatch):
    """El control del test de arriba: `ENV=production` sigue fallando."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("LIBRAAUTH_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("ENV", "production")
    with pytest.raises(ClaveDeCifradoAusente):
        cifrar("algo")


def test_el_secret_key_real_le_gana_al_fallback_de_dev(monkeypatch):
    """Una instancia de dev CON secreto propio usa el suyo, no el generico —
    si no, lo cifrado en dev seria descifrable por cualquiera que conozca la
    constante."""
    monkeypatch.setenv("ENV", "development")
    monkeypatch.delenv("SECRET_KEY", raising=False)
    con_fallback = clave_de_cifrado()
    monkeypatch.setenv("SECRET_KEY", "propio" * 10)
    assert clave_de_cifrado() != con_fallback


def test_sin_secreto_pero_sin_nada_que_cifrar_no_falla(monkeypatch):
    """Una instancia sin SMTP configurado tiene que poder levantar igual."""
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert cifrar("") == ""


def test_el_info_de_hkdf_esta_fijado():
    """Cambiarlo invalida todo lo cifrado hasta ahora. El test existe para
    que sea una decision consciente con una migracion, no un renombre
    distraido."""
    assert crypto._INFO == b"libraauth/cifrado-en-reposo/v1"


# ── Rotacion sin perder lo guardado ──────────────────────────────────────────
#
# Lo que fijan estos tests no es que el AES sepa probar dos claves, sino el
# ciclo completo de una rotacion: leer con la vieja, recifrar con la nueva, y
# poder sacar la variable de transicion sabiendo que ya no hace falta.


def _rotar(monkeypatch, nueva: str, anteriores: str | None = None):
    monkeypatch.setenv("SECRET_KEY", nueva)
    if anteriores is None:
        monkeypatch.delenv(crypto.CLAVES_ANTERIORES, raising=False)
    else:
        monkeypatch.setenv(crypto.CLAVES_ANTERIORES, anteriores)


def test_declarando_la_clave_anterior_lo_guardado_se_sigue_leyendo(monkeypatch):
    blob = cifrar("credencial-de-sos")
    _rotar(monkeypatch, "z" * 64, anteriores="a" * 64)
    assert descifrar(blob) == "credencial-de-sos"


def test_descifrar_al_dia_avisa_que_vino_de_una_clave_vieja(monkeypatch):
    """Sin esta señal la rotacion no se puede dar por cerrada: leer bien no
    distingue "ya esta recifrado" de "todavia depende de la clave vieja"."""
    blob = cifrar("credencial-de-sos")
    assert crypto.descifrar_al_dia(blob) == ("credencial-de-sos", True)
    _rotar(monkeypatch, "z" * 64, anteriores="a" * 64)
    assert crypto.descifrar_al_dia(blob) == ("credencial-de-sos", False)


def test_recifrar_deja_el_valor_bajo_la_clave_vigente(monkeypatch):
    """El ciclo entero: recifrado, el valor sobrevive a SACAR la variable de
    transicion. Es el unico test que prueba que la rotacion se puede terminar."""
    blob = cifrar("credencial-de-sos")
    _rotar(monkeypatch, "z" * 64, anteriores="a" * 64)

    nuevo = crypto.recifrar(blob)
    assert nuevo is not None and nuevo != blob

    _rotar(monkeypatch, "z" * 64, anteriores=None)
    assert descifrar(nuevo) == "credencial-de-sos"
    # Y el control que le da sentido: el viejo YA no se puede leer sin ella.
    with pytest.raises(SecretoIndescifrable):
        descifrar(blob)


def test_recifrar_lo_que_ya_esta_al_dia_devuelve_none(monkeypatch):
    """Idempotencia: una segunda pasada no escribe en la base ni genera nonces
    nuevos, asi que correrlo de mas es gratis y seguro."""
    blob = cifrar("credencial-de-sos")
    assert crypto.recifrar(blob) is None
    assert crypto.recifrar("") is None


def test_recifrar_no_toca_lo_que_no_puede_leer(monkeypatch):
    """Reemplazarlo por algo cifrado con la clave nueva destruiria el unico
    rastro de lo que habia."""
    blob = cifrar("credencial-de-sos")
    _rotar(monkeypatch, "z" * 64, anteriores="clave-que-no-es")
    with pytest.raises(SecretoIndescifrable):
        crypto.recifrar(blob)


def test_cifrar_usa_siempre_la_vigente_aunque_haya_anteriores(monkeypatch):
    """Si `cifrar` pudiera usar una anterior, sacar la variable de transicion
    volveria ilegible algo recien guardado."""
    _rotar(monkeypatch, "z" * 64, anteriores="a" * 64)
    blob = cifrar("recien-cargada")
    _rotar(monkeypatch, "z" * 64, anteriores=None)
    assert descifrar(blob) == "recien-cargada"


def test_se_admiten_varias_claves_anteriores(monkeypatch):
    """Dos rotaciones seguidas sin recifrar en el medio no pueden dejar
    huerfano lo de la primera."""
    viejisimo = cifrar("de-la-primera-epoca")
    _rotar(monkeypatch, "m" * 64, anteriores="a" * 64)
    intermedio = cifrar("de-la-segunda")
    _rotar(monkeypatch, "z" * 64, anteriores=f"{'m' * 64},{'a' * 64}")
    assert descifrar(viejisimo) == "de-la-primera-epoca"
    assert descifrar(intermedio) == "de-la-segunda"


def test_las_claves_anteriores_vacias_se_ignoran(monkeypatch):
    """`"a,,b"` y `" , "` son formas normales de quedar despues de editar la
    variable a mano; una cadena vacia derivaria una clave valida que no es la
    de nadie."""
    _rotar(monkeypatch, "z" * 64, anteriores=f" , ,{'a' * 64}, ")
    assert crypto._materiales_anteriores() == [("a" * 64).encode()]


def test_sin_claves_anteriores_el_mensaje_lo_dice(monkeypatch):
    """El error tiene que llevar a la accion correcta: declarar el valor viejo
    para poder recifrar, en vez de dar la credencial por perdida."""
    blob = cifrar("credencial-de-sos")
    _rotar(monkeypatch, "z" * 64, anteriores=None)
    with pytest.raises(SecretoIndescifrable) as exc:
        descifrar(blob)
    assert crypto.CLAVES_ANTERIORES in str(exc.value)
