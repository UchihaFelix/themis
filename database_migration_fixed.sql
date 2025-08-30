-- Fixed database migration script for Themis user system enhancements
-- Add columns to staff_members table for user settings and passkey authentication

-- Add columns to the existing staff_members table (ignore errors if columns already exist)
ALTER TABLE staff_members ADD COLUMN user_settings JSON DEFAULT '{}';
ALTER TABLE staff_members ADD COLUMN display_name VARCHAR(100) DEFAULT NULL;
ALTER TABLE staff_members ADD COLUMN theme_preference ENUM('system', 'dark', 'light') DEFAULT 'system';
ALTER TABLE staff_members ADD COLUMN language_preference VARCHAR(10) DEFAULT 'en';
ALTER TABLE staff_members ADD COLUMN notification_settings JSON DEFAULT '{"email": true, "discord": true, "in_app": true}';
ALTER TABLE staff_members ADD COLUMN last_login_at TIMESTAMP NULL DEFAULT NULL;
ALTER TABLE staff_members ADD COLUMN login_count INT DEFAULT 0;
ALTER TABLE staff_members ADD COLUMN account_status ENUM('active', 'inactive', 'suspended') DEFAULT 'active';
ALTER TABLE staff_members ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE staff_members ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

-- Create indexes for better performance on existing columns (ignore errors if indexes already exist)
CREATE INDEX idx_staff_members_user_id ON staff_members(user_id);
CREATE INDEX idx_staff_members_rank ON staff_members(rank);
CREATE INDEX idx_staff_members_account_status ON staff_members(account_status);