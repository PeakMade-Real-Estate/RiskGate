"""add trusted locations table

Revision ID: add_trusted_locations
Revises: c34d5ec874d2
Create Date: 2026-07-01 21:50:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime


# revision identifiers, used by Alembic.
revision = 'add_trusted_locations'
down_revision = 'c34d5ec874d2'
branch_labels = None
depends_on = None


def upgrade():
    # Create user_trusted_location table
    op.create_table('user_trusted_location',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('entra_user_id', sa.String(length=100), nullable=False),
    sa.Column('user_principal_name', sa.String(length=255), nullable=False),
    sa.Column('country', sa.String(length=100), nullable=False),
    sa.Column('city', sa.String(length=100), nullable=True),
    sa.Column('latitude', sa.Float(), nullable=False),
    sa.Column('longitude', sa.Float(), nullable=False),
    sa.Column('login_count', sa.Integer(), nullable=True, default=1),
    sa.Column('first_seen', sa.DateTime(), nullable=True, default=datetime.utcnow),
    sa.Column('last_seen', sa.DateTime(), nullable=True, default=datetime.utcnow),
    sa.Column('is_trusted', sa.Boolean(), nullable=True, default=False),
    sa.Column('location_name', sa.String(length=255), nullable=True),
    sa.ForeignKeyConstraint(['entra_user_id'], ['user_identity.entra_user_id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for performance
    op.create_index(op.f('ix_user_trusted_location_entra_user_id'), 'user_trusted_location', ['entra_user_id'], unique=False)
    op.create_index(op.f('ix_user_trusted_location_user_principal_name'), 'user_trusted_location', ['user_principal_name'], unique=False)
    op.create_index(op.f('ix_user_trusted_location_is_trusted'), 'user_trusted_location', ['is_trusted'], unique=False)
    op.create_index(op.f('ix_user_trusted_location_country'), 'user_trusted_location', ['country'], unique=False)


def downgrade():
    # Drop indexes
    op.drop_index(op.f('ix_user_trusted_location_country'), table_name='user_trusted_location')
    op.drop_index(op.f('ix_user_trusted_location_is_trusted'), table_name='user_trusted_location')
    op.drop_index(op.f('ix_user_trusted_location_user_principal_name'), table_name='user_trusted_location')
    op.drop_index(op.f('ix_user_trusted_location_entra_user_id'), table_name='user_trusted_location')
    
    # Drop table
    op.drop_table('user_trusted_location')
