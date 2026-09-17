"""secretos_instancia: los secretos de terceros, cifrados en reposo.

Agrega la tabla que sostiene `libraauth.secretos.SecretosRepository`, para que
los tres secretos que `libracore.config_manager` guardaba en `config.json` en
texto plano —`mp_access_token`, `mp_webhook_secret` y `email_smtp_password`—
pasen a vivir cifrados. El por que esta en `models.SecretoInstancia`.

**Crea la tabla solo si falta, igual que la baseline.** No es una precaucion de
adorno: en las instancias vivas la tabla la puede haber creado ya el
`Base.metadata.create_all()` del arranque —que corre en los ocho productos y no
mira Alembic—, asi que esta revision tiene que poder correr despues de eso y
terminar sin tocar nada. Al reves tambien: una base que reciba la cadena antes
del primer arranque queda con la tabla ya hecha y el `create_all` no la duplica.

**No migra ningun dato.** Sacar el secreto del `config.json` y meterlo aca es
trabajo de `libracore.config_manager.migrar_secretos_al_almacen()`, que corre en
el arranque del producto: Alembic no tiene —ni tiene que tener— acceso al
`DATA_DIR` de la instancia, que es un volumen del contenedor y no la base.
"""
import sqlalchemy as sa
from alembic import op

from libraauth.models import ahora_local

revision = "0002_secretos_instancia"
down_revision = "0001_baseline_libraauth"
branch_labels = None
depends_on = None

TABLA = "secretos_instancia"


def upgrade():
    if TABLA in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        TABLA,
        # La clave ES la PK: un secreto, una fila. Ver `models.SecretoInstancia`.
        sa.Column("clave", sa.String(length=100), nullable=False),
        sa.Column("valor_cifrado", sa.Text(), nullable=False),
        # NOT NULL aunque el modelo no lo diga con `nullable=`: lo dice la
        # anotacion `Mapped[datetime]` (sin `| None`). Mismo criterio que las
        # cuatro columnas de fecha de la baseline.
        sa.Column("actualizado_at", sa.DateTime(), server_default=ahora_local(),
                  nullable=False),
        sa.PrimaryKeyConstraint("clave"),
    )


def downgrade():
    """Bajar esta revision borra los secretos guardados, y **no hay copia**: el
    `config.json` del que salieron queda vacio despues de la migracion.

    Por eso no se baja sola. Si hiciera falta volver a la version anterior del
    paquete, el camino es restaurar el backup de la base — el mismo criterio
    que la baseline, y por una razon mas fuerte: aca lo que se pierde son
    credenciales de terceros que hay que volver a pedirle al cliente.
    """
    raise RuntimeError(
        "Esta revision no se baja: borraria los secretos de terceros de la "
        "instancia (MercadoPago, SMTP) sin ninguna copia. Para volver atras, "
        "restaurar el backup de la base."
    )
