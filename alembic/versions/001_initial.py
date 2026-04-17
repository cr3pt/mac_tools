from alembic import op
import sqlalchemy as sa
revision = '001'; down_revision = None
def upgrade():
    op.create_table('analysis_sessions',
        sa.Column('id',          sa.Integer,    primary_key=True),
        sa.Column('sha256',      sa.String(64), unique=True, nullable=False),
        sa.Column('filename',    sa.String(255)),
        sa.Column('severity',    sa.Integer,    default=0),
        sa.Column('result_json', sa.Text),
        sa.Column('created_at',  sa.DateTime))
def downgrade():
    op.drop_table('analysis_sessions')
