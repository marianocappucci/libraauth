"""`libraauth.totp`: vectores de prueba del RFC 6238 (apendice B, SHA1) y las
reglas propias — un codigo sirve una sola vez, la ventana es de un paso, y un
secreto roto frena en vez de quedar como un 2FA que nunca valida."""
import base64

import pytest

from libraauth import totp

# El secreto de los vectores del RFC: "12345678901234567890" en ASCII.
SECRETO_RFC = base64.b32encode(b"12345678901234567890").decode()


@pytest.mark.parametrize("segundos,esperado", [
    # (tiempo unix, ultimos 6 digitos del valor de 8 del apendice B)
    (59, "287082"),
    (1111111109, "081804"),
    (1234567890, "005924"),
    (2000000000, "279037"),
])
def test_vectores_del_rfc_6238(segundos, esperado):
    clave = totp.decodificar_secreto(SECRETO_RFC)
    assert totp.codigo(clave, segundos // 30) == esperado


def test_generar_secreto_es_base32_de_160_bits_y_distinto_cada_vez():
    a, b = totp.generar_secreto(), totp.generar_secreto()
    assert a != b
    assert len(a) == 32 and "=" not in a
    assert len(totp.decodificar_secreto(a)) == 20


def test_decodificar_tolera_espacios_guiones_y_minusculas():
    s = totp.generar_secreto()
    con_ruido = " ".join([s[:8].lower(), s[8:16], "-", s[16:]])
    assert totp.decodificar_secreto(con_ruido) == totp.decodificar_secreto(s)


@pytest.mark.parametrize("malo", ["", "   ", "no-es-base32!!", "ABCD"])
def test_secreto_invalido_levanta_ValueError(malo):
    with pytest.raises(ValueError):
        totp.decodificar_secreto(malo)


def test_uri_otpauth_lleva_secreto_emisor_y_cuenta():
    uri = totp.uri_otpauth(SECRETO_RFC, "gestiolibra")
    assert uri.startswith("otpauth://totp/Libra%20Backoffice%3Agestiolibra?")
    assert f"secret={SECRETO_RFC}" in uri
    assert "issuer=Libra+Backoffice" in uri
    assert "digits=6" in uri and "period=30" in uri


class TestPasoValido:
    def _t(self):
        return totp.Totp(SECRETO_RFC)

    def test_codigo_actual_vale_y_devuelve_su_paso(self):
        assert self._t().paso_valido("005924", ahora=1234567890) == 1234567890 // 30

    def test_paso_anterior_y_siguiente_valen_mas_alla_no(self):
        t = self._t()
        clave = totp.decodificar_secreto(SECRETO_RFC)
        paso = 1234567890 // 30
        assert t.paso_valido(totp.codigo(clave, paso - 1), ahora=1234567890) == paso - 1
        assert t.paso_valido(totp.codigo(clave, paso + 1), ahora=1234567890) == paso + 1
        assert t.paso_valido(totp.codigo(clave, paso - 2), ahora=1234567890) is None
        assert t.paso_valido(totp.codigo(clave, paso + 2), ahora=1234567890) is None

    def test_un_codigo_sirve_una_sola_vez(self):
        """Quien vio el codigo recien usado no puede reusarlo dentro de la ventana."""
        t = self._t()
        paso = t.paso_valido("005924", ahora=1234567890)
        assert paso is not None
        assert t.paso_valido("005924", ultimo_paso=paso, ahora=1234567890) is None
        # Y tampoco vale un codigo de un paso ANTERIOR al ultimo aceptado.
        clave = totp.decodificar_secreto(SECRETO_RFC)
        assert t.paso_valido(totp.codigo(clave, paso - 1), ultimo_paso=paso, ahora=1234567890) is None

    @pytest.mark.parametrize("malo", ["", "12345", "1234567", "abcdef", "00592a", None])
    def test_forma_invalida_no_vale(self, malo):
        assert self._t().paso_valido(malo, ahora=1234567890) is None

    def test_tolera_espacios_en_el_codigo(self):
        assert self._t().paso_valido(" 005 924 ", ahora=1234567890) is not None


def test_main_imprime_secreto_y_uri(capsys):
    assert totp.main(["contalibra"]) == 0
    salida = capsys.readouterr().out.splitlines()
    assert salida[0].startswith("ADMIN_PANEL_TOTP_SECRET=")
    secreto = salida[0].split("=", 1)[1]
    assert salida[1] == totp.uri_otpauth(secreto, "contalibra")
