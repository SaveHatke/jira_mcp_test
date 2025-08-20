"""Initial migration with user and configuration models

Revision ID: 001
Revises: 
Create Date: 2024-12-19 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial tables for users and configurations."""
    
    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('employee_id', sa.String(length=50), nullable=False, comment='Employee ID from Jira (used as username)'),
        sa.Column('name', sa.String(length=100), nullable=False, comment='Full name from Jira user profile'),
        sa.Column('email', sa.String(length=255), nullable=False, comment='Email address from Jira user profile'),
        sa.Column('display_name', sa.String(length=100), nullable=False, comment='Display name from Jira user profile'),
        sa.Column('hashed_password', sa.String(length=255), nullable=False, comment='Bcrypt hashed password'),
        sa.Column('encrypted_jira_pat', sa.Text(), nullable=False, comment='AES-256 encrypted Jira Personal Access Token'),
        sa.Column('jira_url', sa.String(length=500), nullable=False, comment='Base Jira URL extracted from user profile'),
        sa.Column('avatar_url', sa.String(length=500), nullable=True, comment='Avatar URL from Jira (48x48)'),
        sa.Column('active', sa.Boolean(), nullable=False, comment='Whether the user account is active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('employee_id'),
        sa.UniqueConstraint('email')
    )
    
    # Create indexes for users table
    op.create_index('idx_user_employee_id', 'users', ['employee_id'])
    op.create_index('idx_user_email', 'users', ['email'])
    op.create_index('idx_user_active', 'users', ['active'])
    
    # Create user_sessions table
    op.create_table('user_sessions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='Reference to the user who owns this session'),
        sa.Column('token_hash', sa.String(length=255), nullable=False, comment='SHA-256 hash of the JWT token'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False, comment='When this session expires'),
        sa.Column('user_agent', sa.String(length=500), nullable=True, comment='User agent string from the client'),
        sa.Column('ip_address', sa.String(length=45), nullable=True, comment='Client IP address'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash')
    )
    
    # Create indexes for user_sessions table
    op.create_index('idx_session_user_id', 'user_sessions', ['user_id'])
    op.create_index('idx_session_token_hash', 'user_sessions', ['token_hash'])
    op.create_index('idx_session_expires_at', 'user_sessions', ['expires_at'])
    
    # Create llm_configs table
    op.create_table('llm_configs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='Reference to the user who owns this configuration'),
        sa.Column('encrypted_cookie', sa.Text(), nullable=False, comment='AES-256 encrypted cookie value for LLM authentication'),
        sa.Column('tested_at', sa.DateTime(timezone=True), nullable=True, comment='When this configuration was last successfully tested'),
        sa.Column('test_success', sa.Boolean(), nullable=True, comment='Result of the last configuration test'),
        sa.Column('test_error_message', sa.Text(), nullable=True, comment='Error message from last failed test (if any)'),
        sa.Column('llm_user_id', sa.String(length=100), nullable=True, comment='User ID returned by LLM service for validation'),
        sa.Column('llm_username', sa.String(length=100), nullable=True, comment='Username returned by LLM service for validation'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id')
    )
    
    # Create indexes for llm_configs table
    op.create_index('idx_llm_config_user_id', 'llm_configs', ['user_id'])
    op.create_index('idx_llm_config_tested_at', 'llm_configs', ['tested_at'])
    
    # Create confluence_configs table
    op.create_table('confluence_configs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='Reference to the user who owns this configuration'),
        sa.Column('url', sa.String(length=500), nullable=False, comment='Confluence base URL'),
        sa.Column('encrypted_pat', sa.Text(), nullable=False, comment='AES-256 encrypted Confluence Personal Access Token'),
        sa.Column('verify_ssl', sa.Boolean(), nullable=False, comment='Whether to verify SSL certificates'),
        sa.Column('ssl_cert_path', sa.String(length=500), nullable=True, comment='Path to custom SSL certificate file'),
        sa.Column('tested_at', sa.DateTime(timezone=True), nullable=True, comment='When this configuration was last successfully tested'),
        sa.Column('test_success', sa.Boolean(), nullable=True, comment='Result of the last configuration test'),
        sa.Column('test_error_message', sa.Text(), nullable=True, comment='Error message from last failed test (if any)'),
        sa.Column('confluence_user_id', sa.String(length=100), nullable=True, comment='User ID returned by Confluence for validation'),
        sa.Column('confluence_username', sa.String(length=100), nullable=True, comment='Username returned by Confluence for validation'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id')
    )
    
    # Create indexes for confluence_configs table
    op.create_index('idx_confluence_config_user_id', 'confluence_configs', ['user_id'])
    op.create_index('idx_confluence_config_tested_at', 'confluence_configs', ['tested_at'])
    
    # Create tool_cache table
    op.create_table('tool_cache',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='Reference to the user who owns this cache entry'),
        sa.Column('source', sa.String(length=20), nullable=False, comment='Source of the tools (jira, confluence)'),
        sa.Column('tool_data', sa.Text(), nullable=False, comment='JSON serialized tool list data'),
        sa.Column('refreshed_at', sa.DateTime(timezone=True), nullable=False, comment='When this cache entry was last refreshed'),
        sa.Column('ttl_seconds', sa.Integer(), nullable=False, comment='Time-to-live for this cache entry in seconds'),
        sa.Column('tool_count', sa.Integer(), nullable=True, comment='Number of tools in the cached data'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for tool_cache table
    op.create_index('idx_tool_cache_user_source', 'tool_cache', ['user_id', 'source'])
    op.create_index('idx_tool_cache_refreshed_at', 'tool_cache', ['refreshed_at'])
    
    # Create background_jobs table
    op.create_table('background_jobs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, comment='Reference to the user who owns this job'),
        sa.Column('job_type', sa.String(length=50), nullable=False, comment='Type of background job (tool_refresh, ai_generation, etc.)'),
        sa.Column('job_id', sa.String(length=100), nullable=True, comment='Unique job ID from Huey'),
        sa.Column('payload', sa.Text(), nullable=True, comment='JSON serialized job parameters'),
        sa.Column('status', sa.String(length=20), nullable=False, comment='Job status (pending, running, completed, failed)'),
        sa.Column('result', sa.Text(), nullable=True, comment='JSON serialized job result or error message'),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True, comment='When job execution started'),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True, comment='When job execution completed'),
        sa.Column('retry_count', sa.Integer(), nullable=False, comment='Number of retry attempts'),
        sa.Column('max_retries', sa.Integer(), nullable=False, comment='Maximum number of retry attempts'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('job_id')
    )
    
    # Create indexes for background_jobs table
    op.create_index('idx_background_job_user_id', 'background_jobs', ['user_id'])
    op.create_index('idx_background_job_status', 'background_jobs', ['status'])
    op.create_index('idx_background_job_type', 'background_jobs', ['job_type'])
    op.create_index('idx_background_job_created_at', 'background_jobs', ['created_at'])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table('background_jobs')
    op.drop_table('tool_cache')
    op.drop_table('confluence_configs')
    op.drop_table('llm_configs')
    op.drop_table('user_sessions')
    op.drop_table('users')