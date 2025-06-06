"""Criação da tabela User

Revision ID: 0fa2148c01ad
Revises: 40abaa3bd87c
Create Date: 2025-05-20 15:21:56.840027

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0fa2148c01ad'
down_revision = '40abaa3bd87c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('last_login',
               existing_type=sa.INTEGER(),
               type_=sa.DateTime(),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('last_login',
               existing_type=sa.DateTime(),
               type_=sa.INTEGER(),
               existing_nullable=True)

    # ### end Alembic commands ###
