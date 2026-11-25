-- NetShield AI MySQL Schema (netshield_ai)
CREATE DATABASE IF NOT EXISTS netshield_ai
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE netshield_ai;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'analyst', 'viewer') NOT NULL DEFAULT 'analyst',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_users_role (role)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS network_events (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_time DATETIME NOT NULL,
  src_ip VARCHAR(45) NOT NULL,
  dst_ip VARCHAR(45) NOT NULL,
  src_port INT UNSIGNED NOT NULL,
  dst_port INT UNSIGNED NOT NULL,
  protocol VARCHAR(16) NOT NULL,
  prediction ENUM('Normal', 'Attack') NOT NULL,
  score DECIMAL(5, 4) NOT NULL,
  model_version VARCHAR(32) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_events_time (event_time),
  INDEX idx_events_prediction (prediction),
  INDEX idx_events_src_ip (src_ip),
  INDEX idx_events_dst_ip (dst_ip)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alerts (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_id BIGINT NOT NULL,
  severity ENUM('Low', 'Medium', 'High', 'Critical') NOT NULL,
  status ENUM('Open', 'Investigating', 'Resolved') NOT NULL DEFAULT 'Open',
  description VARCHAR(500) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at DATETIME NULL,
  CONSTRAINT fk_alerts_event
    FOREIGN KEY (event_id) REFERENCES network_events(id)
    ON DELETE CASCADE,
  INDEX idx_alerts_status_severity (status, severity),
  INDEX idx_alerts_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS model_registry (
  id INT AUTO_INCREMENT PRIMARY KEY,
  version VARCHAR(32) NOT NULL UNIQUE,
  algorithm VARCHAR(64) NOT NULL,
  accuracy DECIMAL(5, 4) NOT NULL,
  precision_score DECIMAL(5, 4) NOT NULL,
  recall_score DECIMAL(5, 4) NOT NULL,
  f1_score DECIMAL(5, 4) NOT NULL,
  artifact_path VARCHAR(255) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_model_active (is_active)
) ENGINE=InnoDB;
