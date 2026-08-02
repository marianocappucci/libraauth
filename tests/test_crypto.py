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


def test_rotar_el_secret_key_da_secreto_indescifrable(monkeypatch):
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
