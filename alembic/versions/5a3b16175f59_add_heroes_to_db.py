"""Add heroes to db

Revision ID: 5a3b16175f59
Revises: 3b3ffd41dfc4
Create Date: 2015-08-16 16:43:06.260335

"""

# revision identifiers, used by Alembic.
revision = '5a3b16175f59'
down_revision = '3b3ffd41dfc4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('heroes',
    sa.Column('id', sa.Integer(), autoincrement=False, nullable=False),
    sa.Column('name', sa.String(length=80), nullable=True),
    sa.Column('token', sa.String(length=80), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.drop_index(u'ix_replay_players_hero_id', table_name='replay_players')
    ### end Alembic commands ###


def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_index(u'ix_replay_players_hero_id', 'replay_players', [u'hero_id'], unique=False)
    op.drop_table('heroes')
    ### end Alembic commands ###
