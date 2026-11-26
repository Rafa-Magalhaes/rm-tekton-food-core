CREATE TABLE users (
                       id UUID PRIMARY KEY,
                       name VARCHAR(120) NOT NULL,
                       email VARCHAR(180) NOT NULL,
                       password_hash VARCHAR(255) NOT NULL,
                       role VARCHAR(30) NOT NULL,
                       active BOOLEAN NOT NULL DEFAULT TRUE,
                       created_at TIMESTAMPTZ NOT NULL,
                       updated_at TIMESTAMPTZ NOT NULL,
                       CONSTRAINT uk_users_email UNIQUE (email)
);

CREATE INDEX idx_users_email_active ON users (email) WHERE active = TRUE;