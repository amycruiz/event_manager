"""initial migration

Revision ID: ef1d775276c0
Revises: 
Create Date: 2024-04-20 21:20:32.839580

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import uuid

# revision identifiers, used by Alembic.
revision: str = 'ef1d775276c0'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.UUID(), nullable=False),
    sa.Column('nickname', sa.String(length=50), nullable=False),
    sa.Column('email', sa.String(length=255), nullable=False),
    sa.Column('first_name', sa.String(length=100), nullable=True),
    sa.Column('last_name', sa.String(length=100), nullable=True),
    sa.Column('bio', sa.String(length=500), nullable=True),
    sa.Column('profile_picture_url', sa.String(length=255), nullable=True),
    sa.Column('linkedin_profile_url', sa.String(length=255), nullable=True),
    sa.Column('github_profile_url', sa.String(length=255), nullable=True),
    sa.Column('role', sa.Enum('ANONYMOUS', 'AUTHENTICATED', 'MANAGER', 'ADMIN', name='UserRole'), nullable=False),
    sa.Column('is_professional', sa.Boolean(), nullable=True),
    sa.Column('professional_status_updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('failed_login_attempts', sa.Integer(), nullable=True),
    sa.Column('is_locked', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
    sa.Column('verification_token', sa.String(), nullable=True),
    sa.Column('email_verified', sa.Boolean(), nullable=False),
    sa.Column('hashed_password', sa.String(length=255), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_nickname'), 'users', ['nickname'], unique=True)
    # ### end Alembic commands ###
    
    # ### Add an admin account ###
    admin_id = str(uuid.uuid4())  # Generate a UUID for the admin user
    admin_email = 'admin@example.com'
    admin_nickname = 'admin'
    admin_hash_password = '$2b$12$wMygvJfsJGS4UqdeKF1JGO6Sd7tQBg8uo6C946xgntDsstrdgTKVy'

    op.execute(f"""
        INSERT INTO users (id, nickname, email, role, email_verified, hashed_password, created_at, updated_at)
        VALUES (
            '{admin_id}', 
            '{admin_nickname}', 
            '{admin_email}', 
            'ADMIN', 
            TRUE, 
            '{admin_hash_password}', 
            now(), 
            now()
        )
    """)


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_nickname'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
    # ### end Alembic commands ###
