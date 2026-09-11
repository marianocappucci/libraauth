"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

🔴 Antes de alterar una tabla que ya existe, medir las bases vivas con
`libraauth-migrar diferencias`: `usuarios` y `auth_log` no tienen la misma forma
en todas (ver la baseline). Y la revision tiene que ser idempotente: el
`create_all()` del arranque de un producto puede haber llegado antes que ella.

🔴 El id de la revision, **32 caracteres o menos**: `alembic_version_libraauth`
la crea alembic con `version_num VARCHAR(32)`, y PostgreSQL no trunca — el
`upgrade` moriria al escribir la version, despues de haber aplicado el DDL.
"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade():
    ${upgrades if upgrades else "pass"}


def downgrade():
    ${downgrades if downgrades else "pass"}
