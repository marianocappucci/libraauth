"""Baseline: el schema de auth tal como lo crea hoy `create_all()`.

**Crea solo las tablas que falten y no toca ninguna que ya exista.** Es lo mismo
que hace `Base.metadata.create_all()` en cada arranque de los ocho productos —de
ahi sale que sea segura sobre una instancia viva: una base con las seis tablas
termina exactamente como estaba, mas la fila de `alembic_version_libraauth`—.
Por eso las instancias existentes **se migran con `upgrade`, no se estampan a
ciegas**, igual que en LibraCore y LibraCommerce.

**Por que el DDL esta escrito aca y no es una llamada a `create_all()`.** Las
baselines de LibraCore y LibraCommerce llaman a la funcion que ya existia porque
esa funcion quedo **congelada**. Aca la "funcion" son los modelos, y los modelos
van a seguir cambiando: una baseline que llamara a `create_all()` crearia en una
base vacia la forma de la *cabeza* —con las columnas que agregue la `0002`— y la
`0002` moriria al querer agregarlas de nuevo. Esta revision es la foto del
modelo al 2026-09-11 (libraauth `v0.38.0`) y desde aca **es de solo lectura**.
Que la foto coincida con el modelo lo sostiene
`test_modelo_y_cadena_coinciden`, no la memoria de nadie.

🔴 **Lo que esta baseline NO normaliza, y por que.** `usuarios` y `auth_log`
los declaran dos motores: este y el DDL crudo de LibraCore
(`libracore.db.schema`), que los crea con columnas `TEXT` y `auth_log.ts` como
texto. En cada base quedo la forma de quien llego primero —en Contalibra,
Restolibra y las bases de LibraCore de Gestiolibra, MedLibra y VentaLibra, casi
siempre LibraCore; en LibraDesk, LibraCargo y LibraClub, este modelo, y en
LibraDesk `auth_log.ts` sin DEFAULT por venir de antes de la `v0.15.0`—. El
codigo ya tolera las dos formas (`auth_events._ts_es_texto`, `ts_legible`), y
llevarlas a una sola es un `ALTER` con datos adentro: si algun dia hace falta,
es una revision propia, escrita despues de medir cada base con
`libraauth-migrar diferencias`. Una baseline que lo intentara de pasada
cambiaria datos en la primera corrida, que es lo que no puede hacer.
"""
import sqlalchemy as sa
from alembic import op

from libraauth.models import ahora_local

revision = "0001_baseline_libraauth"
down_revision = None
branch_labels = None
depends_on = None


def _crear_usuarios():
    op.create_table(
        "usuarios",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("nombre", sa.String(length=200), nullable=False),
        sa.Column("email", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("activo", sa.Boolean(), nullable=False),
        # NOT NULL aunque el modelo no lo diga con `nullable=`: lo dice la
        # anotacion `Mapped[datetime]` (sin `| None`). Es la foto de lo que emite
        # `create_all`, y la primera version de esta baseline la tenia mal —la
        # agarro `test_modelo_y_cadena_coinciden`—. Vale para las otras tres
        # columnas de fecha con `server_default` de esta revision.
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )


def _crear_password_reset_tokens():
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["usuarios.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens",
                    ["user_id"], unique=False)


def _crear_auth_log():
    op.create_table(
        "auth_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        # El DEFAULT del servidor es el que usa el INSERT crudo de
        # `libracore.db.logs` (sin `ts`). Ver `models.AuthEvent.ts`.
        sa.Column("ts", sa.DateTime(), server_default=ahora_local(), nullable=False),
        sa.Column("evento", sa.String(length=50), nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=True),
        sa.Column("detalle", sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def _crear_smtp_settings():
    op.create_table(
        "smtp_settings",
        # Fila unica con id fijo en 1, pero el modelo lo declara igual que el
        # resto (serial en PostgreSQL): la foto es la de `create_all`, no la
        # que "deberia" ser.
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("host", sa.String(length=200), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("user", sa.String(length=200), nullable=False),
        sa.Column("password_cifrada", sa.Text(), nullable=False),
        sa.Column("from_email", sa.String(length=200), nullable=False),
        sa.Column("from_name", sa.String(length=200), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def _crear_demo_codigos():
    op.create_table(
        "demo_codigos",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("codigo_hash", sa.String(length=64), nullable=False),
        sa.Column("prefijo", sa.String(length=8), nullable=False),
        sa.Column("etiqueta", sa.String(length=200), nullable=False),
        sa.Column("emitido_por", sa.String(length=100), nullable=False),
        sa.Column("creado_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("usos_max", sa.Integer(), nullable=False),
        sa.Column("usos", sa.Integer(), nullable=False),
        sa.Column("ultimo_uso", sa.DateTime(), nullable=True),
        sa.Column("revocado", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    # `unique=True, index=True` en el modelo: `create_all` lo emite como UN
    # indice unico, no como constraint + indice. Se replica tal cual.
    op.create_index("ix_demo_codigos_codigo_hash", "demo_codigos", ["codigo_hash"],
                    unique=True)


def _crear_aceptaciones_terminos():
    op.create_table(
        "aceptaciones_terminos",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("usuario_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("nombre", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=20), nullable=False),
        sa.Column("hash_texto", sa.String(length=64), nullable=False),
        sa.Column("aceptado_at", sa.DateTime(), server_default=ahora_local(), nullable=False),
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("user_agent", sa.String(length=400), nullable=False),
        sa.ForeignKeyConstraint(["usuario_id"], ["usuarios.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_aceptaciones_terminos_usuario_id", "aceptaciones_terminos",
                    ["usuario_id"], unique=False)
    op.create_index("ix_aceptaciones_terminos_version", "aceptaciones_terminos",
                    ["version"], unique=False)


#: En orden de FK: `usuarios` antes que las dos tablas que la referencian.
TABLAS = (
    ("usuarios", _crear_usuarios),
    ("password_reset_tokens", _crear_password_reset_tokens),
    ("auth_log", _crear_auth_log),
    ("smtp_settings", _crear_smtp_settings),
    ("demo_codigos", _crear_demo_codigos),
    ("aceptaciones_terminos", _crear_aceptaciones_terminos),
)


def upgrade():
    existentes = set(sa.inspect(op.get_bind()).get_table_names())
    for nombre, crear in TABLAS:
        # 🔑 Tabla por tabla y no "todo o nada": una instancia con un pin viejo
        # puede tener cuatro de las seis (`demo_codigos` llego en v0.26.0,
        # `aceptaciones_terminos` en v0.30.0). Es lo mismo que haria
        # `create_all` en el proximo arranque.
        if nombre not in existentes:
            crear()


def downgrade():
    # Bajar de la baseline es borrar `usuarios` y la prueba de aceptacion de los
    # terminos, con los datos adentro. No hay caso de uso que lo justifique: el
    # rollback de esta revision es restaurar el backup. Mismo criterio que las
    # baselines de LibraCore y LibraCommerce.
    raise RuntimeError(
        "La baseline de libraauth no se baja: seria borrar usuarios y "
        "aceptaciones de terminos. Para volver atras, restaurar el backup."
    )
