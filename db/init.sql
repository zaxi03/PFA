USE flask_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    nom VARCHAR(100) NOT NULL,
    prenom VARCHAR(100) NOT NULL
);

INSERT INTO users (email, password, nom, prenom)
SELECT * FROM (
    SELECT 'admin@example.com', 'scrypt:32768:8:1$F2kacIGKfeiLuokS$52c151de7612c2122f6ee1fc07e8e7653704807fa6b95f957e95ce1fc8c02272fc7ffe986582b9e2161a9dbc9e3b3e535650c0a4aacf80175b24e7e3705478dc', 'Zakariae', 'El Meskem'
) AS tmp
WHERE NOT EXISTS (
    SELECT email FROM users WHERE email = 'admin@example.com'
) LIMIT 1;

CREATE TABLE waf_logs (
    id INT NOT NULL AUTO_INCREMENT,
    client_ip VARCHAR(45) COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
    host_cible VARCHAR(255) COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
    uri VARCHAR(255) COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
    method VARCHAR(10) COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
    attack_type VARCHAR(100) COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
    status VARCHAR(30) COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
    created_at DATETIME DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS waf_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_id INT UNIQUE NOT NULL,
    variables JSON,
    operators TEXT,
    actions JSON,
    origin_file VARCHAR(255),
    description TEXT,
    status ENUM('active', 'inactive') DEFAULT 'active'
);

CREATE TABLE blocked_ips (
  id int NOT NULL,
  ip_address varchar(45) NOT NULL,
  blocked_at timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE firewall_rules (
  id int NOT NULL,
  protocol varchar(10) NOT NULL,
  port int NOT NULL,
  action varchar(10) NOT NULL,
  source_ip varchar(45) NOT NULL,
  destination_ip varchar(45) NOT NULL,
  comment text,
  created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
