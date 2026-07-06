"""Add state column to entra_sign_in_event table

Revision ID: 20260706_add_state
Revises: c34d5ec874d2
Create Date: 2026-07-06 10:59:34

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '20260706_add_state'
down_revision = 'c34d5ec874d2'
branch_labels = None
depends_on = None


def upgrade():
    # Add state column to entra_sign_in_event table
    op.add_column('entra_sign_in_event', sa.Column('state', sa.String(length=100), nullable=True))


def downgrade():
    # Remove state column from entra_sign_in_event table
    op.drop_column('entra_sign_in_event', 'state')
