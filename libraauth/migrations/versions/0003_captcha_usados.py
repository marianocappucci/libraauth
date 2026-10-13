"""captcha_usados: los desafios de captcha ya resueltos, compartidos entre procesos.

Agrega la tabla que sostiene `libraauth.captcha.UsadosEnBase` (ADR-023): una fila
por desafio resuelto, con la firma como PK para que `INSERT ... ON CONFLICT DO
NOTHING` diga atomicamente quien fue el primero. Sin ella, con `uvicorn --workers
N` un desafio resuelto servia una vez por worker. El por que esta en
`models.CaptchaUsado`.

**Crea la tabla solo si falta, igual que la baseline y la `0002`:** en una
instancia donde el `Base.metadata.create_all()` del arranque ya la haya hecho, esta
revision termina sin tocar nada. Y el indice sobre `vence` (lo usa la poda) se crea
solo si falta tambien.

**No migra datos y es inocua para los productos que no la usan:** una tabla vacia al
lado de las demas. Pero la cabeza de la cadena cambia, y `exigir_schema_al_dia` exige
que el deploy la haya corrido: subir el pin de libraauth sin correr `libraauth-migrar`
deja al producto sin arrancar, con el comando en el mensaje.
"""
import sqlalchemy as sa
from alembic import op

revision = "0003_captcha_usados"
down_revision = "0002_secretos_instancia"
branch_labels = None
depends_on = None

TABLA = "libraauth_captcha_usados"
INDICE = "ix_libraauth_captcha_usados_vence"


def upgrade():
    inspector = sa.inspect(op.get_bind())
    if TABLA not in set(inspector.get_table_names()):
        op.create_table(
            TABLA,
            sa.Column("firma", sa.String(length=128), nullable=False),
            sa.Column("vence", sa.Float(), nullable=False),
            sa.PrimaryKeyConstraint("firma"),
        )
        op.create_index(INDICE, TABLA, ["vence"])
        return
    if INDICE not in {i["name"] for i in inspector.get_indexes(TABLA)}:
        op.create_index(INDICE, TABLA, ["vence"])


def downgrade():
    """Se puede bajar: la tabla es un cerrojo de vida corta (los desafios duran 10
    minutos) y no guarda nada que haya que conservar. Lo unico que se pierde es el
    anti-replay de los desafios que estaban en vuelo."""
    op.drop_table(TABLA)
