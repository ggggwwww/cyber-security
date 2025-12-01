CREATE DATABASE waf_log;

CREATE USER 'logmanager'@'localhost' IDENTIFIED BY '1234';
GRANT ALL PRIVILEGES ON waf_log.* TO 'logmanager'@'localhost';

CREATE TABLE access_logs (
	log_id INT PRIMARY KEY AUTO_INCREMENT,
	contents TEXT,
	log_date DATETIME NOT NULL,
    action_location VARCHAR(50) NOT NULL
);

INSERT INTO access_logs VALUE();

CREATE TABLE error_logs (
	log_id INT PRIMARY KEY AUTO_INCREMENT,
	contents TEXT,
    log_date DATETIME NOT NULL,
    action_location VARCHAR(50) NOT NULL
);
	
