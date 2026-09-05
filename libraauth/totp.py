"""
TOTP (RFC 6238) con la biblioteca estandar, para el segundo factor del
backoffice de superadmin (`AdminAuth`, F2 del plan de la familia, 2026-09-05).

Sin dependencia nueva a proposito: el algoritmo son quince lineas de HMAC-SHA1
sobre el contador de 30 segundos, y los ocho backoffices tienen un unico
usuario. Lo que un paquete de terceros agregaria —otros hashes, otros largos—
no se usa: los autenticadores comunes (Google Authenticator, Authy, 1Password,
Bitwarden) hablan exactamente esta variante: SHA1, 6 digitos, 30 segundos.

Como se enrola el superadmin:

    python -m libraauth.totp <producto>

imprime un secreto nuevo (base32, 160 bits) y la URI `otpauth://` para cargarlo
en el autenticador. El secreto va a `ADMIN_PANEL_TOTP_SECRET` en el `.env` del
backoffice (`/etc/<producto>-admin.env`), al lado de `ADMIN_PANEL_PASSWORD`, y
desde el siguiente arranque el login pide el codigo.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import sys
import time
import urllib.parse

#: Parametros fijos de la variante que entienden todos los autenticadores.
PASO_SEGUNDOS = 30
DIGITOS = 6

#: Emisor que muestra el autenticador arriba de la cuenta.
EMISOR = "Libra Backoffice"


def generar_secreto() -> str:
    """Secreto nuevo de 160 bits en base32 (32 caracteres, sin relleno)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def decodificar_secreto(secreto: str) -> bytes:
    """Base32 a bytes, tolerando espacios, guiones y minusculas (asi lo pegan
    los autenticadores y asi lo tipea una persona).

    Levanta `ValueError` ante un secreto vacio, que no sea base32 o que sea
    demasiado corto: un secreto mal cargado tiene que frenar el arranque del
    backoffice, no dejar un segundo factor que nunca valida."""
    limpio = (secreto or "").strip().replace(" ", "").replace("-", "").upper()
    if not limpio:
        raise ValueError("el secreto TOTP esta vacio")
    limpio += "=" * (-len(limpio) % 8)
    try:
        clave = base64.b32decode(limpio, casefold=True)
    except Exception as e:  # binascii.Error hereda de ValueError
        raise ValueError(f"el secreto TOTP no es base32 valido ({e})") from None
    if len(clave) < 10:
        raise ValueError("el secreto TOTP es demasiado corto: minimo 80 bits (16 caracteres base32)")
    return clave


def codigo(clave: bytes, paso: int) -> str:
    """El codigo de 6 digitos para un contador dado (RFC 4226 §5.3 sobre el
    contador de tiempo de RFC 6238)."""
    mac = hmac.new(clave, struct.pack(">Q", paso), hashlib.sha1).digest()
    desplazamiento = mac[-1] & 0x0F
    numero = struct.unpack(">I", mac[desplazamiento:desplazamiento + 4])[0] & 0x7FFFFFFF
    return f"{numero % (10 ** DIGITOS):0{DIGITOS}d}"


def uri_otpauth(secreto: str, cuenta: str, emisor: str = EMISOR) -> str:
    """La URI que se carga en el autenticador (como QR o pegada a mano)."""
    etiqueta = urllib.parse.quote(f"{emisor}:{cuenta}")
    parametros = urllib.parse.urlencode({
        "secret": secreto.strip().replace(" ", "").upper(),
        "issuer": emisor,
        "algorithm": "SHA1",
        "digits": DIGITOS,
        "period": PASO_SEGUNDOS,
    })
    return f"otpauth://totp/{etiqueta}?{parametros}"


class Totp:
    """Validador de codigos para un secreto. `ventana=1` acepta el codigo del
    paso anterior y del siguiente ademas del actual: cubre el desfase de reloj
    entre el telefono y el servidor sin abrir mas que 90 segundos."""

    def __init__(self, secreto: str, *, ventana: int = 1):
        self.clave = decodificar_secreto(secreto)
        self.ventana = ventana

    def paso_valido(self, codigo_tipeado: str, *, ultimo_paso: int = 0,
                    ahora: float | None = None) -> int | None:
        """El contador al que corresponde `codigo_tipeado`, o `None` si no vale.

        `ultimo_paso` es el ultimo contador ya aceptado: **un codigo sirve una
        sola vez**. Sin esto, quien mire por encima del hombro un codigo recien
        usado tiene hasta 90 segundos para reusarlo. Quien llama guarda el
        contador devuelto y lo pasa en la siguiente validacion.

        Recorre la ventana entera aunque ya haya encontrado el codigo: que la
        respuesta tarde lo mismo valga o no."""
        limpio = (codigo_tipeado or "").strip().replace(" ", "")
        if len(limpio) != DIGITOS or not limpio.isdigit():
            return None
        paso_actual = int((time.time() if ahora is None else ahora) // PASO_SEGUNDOS)
        encontrado: int | None = None
        for desfase in range(-self.ventana, self.ventana + 1):
            paso = paso_actual + desfase
            if hmac.compare_digest(codigo(self.clave, paso), limpio) and encontrado is None:
                encontrado = paso
        if encontrado is None or encontrado <= ultimo_paso:
            return None
        return encontrado


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cuenta = argv[0] if argv else "superadmin"
    secreto = generar_secreto()
    print("ADMIN_PANEL_TOTP_SECRET=" + secreto)
    print(uri_otpauth(secreto, cuenta))
    print(
        "\nCargar la primera linea en el .env del backoffice y la URI en el "
        "autenticador (como QR o pegando el secreto a mano). El secreto se muestra "
        "una sola vez: no queda guardado en ningun lado.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
