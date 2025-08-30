-- Database migration script for Themis user system enhancements
-- Add columns to staff_members table for user settings and passkey authentication

-- First, let's add columns to the existing staff_members table
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS user_settings JSON DEFAULT '{}';
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS display_name VARCHAR(100) DEFAULT NULL;
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS theme_preference ENUM('system', 'dark', 'light') DEFAULT 'system';
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS language_preference VARCHAR(10) DEFAULT 'en';
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS notification_settings JSON DEFAULT '{"email": true, "discord": true, "in_app": true}';
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP NULL DEFAULT NULL;
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS login_count INT DEFAULT 0;
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS account_status ENUM('active', 'inactive', 'suspended') DEFAULT 'active';
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE staff_members ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

-- Create table for passkey credentials
CREATE TABLE IF NOT EXISTS user_passkeys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    credential_id VARCHAR(255) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter BIGINT DEFAULT 0,
    device_name VARCHAR(100) DEFAULT 'Unnamed Device',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL DEFAULT NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_credential_id (credential_id),
    FOREIGN KEY (user_id) REFERENCES staff_members(user_id) ON DELETE CASCADE
);

-- Create table for user sessions
CREATE TABLE IF NOT EXISTS user_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_session_id (session_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),
    FOREIGN KEY (user_id) REFERENCES staff_members(user_id) ON DELETE CASCADE
);

-- Create table for login attempts and security logging
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT DEFAULT NULL,
    username VARCHAR(255) DEFAULT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    method ENUM('discord', 'passkey') NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_ip_address (ip_address),
    INDEX idx_created_at (created_at),
    INDEX idx_success (success)
);

-- Create indexes for better performance on existing columns
CREATE INDEX IF NOT EXISTS idx_staff_members_user_id ON staff_members(user_id);
CREATE INDEX IF NOT EXISTS idx_staff_members_rank ON staff_members(rank);
CREATE INDEX IF NOT EXISTS idx_staff_members_account_status ON staff_members(account_status);