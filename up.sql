CREATE TABLE IF NOT EXISTS applications
(
    application_id VARCHAR(255) PRIMARY KEY,
    name           VARCHAR(255) NOT NULL,
    description    TEXT
);

CREATE TABLE IF NOT EXISTS users
(
    user_id         VARCHAR(255) PRIMARY KEY,
    username        VARCHAR(255) NOT NULL,
    password        VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    last_login      TIMESTAMP,
    last_ip         VARCHAR(255),
    registration_ip VARCHAR(255),
    application_id  VARCHAR(255),
    foreign key (application_id)
        references applications (application_id)
);

CREATE TABLE IF NOT EXISTS admins
(
    admin_id        VARCHAR(255) PRIMARY KEY,
    username        VARCHAR(255) NOT NULL,
    password        VARCHAR(255) NOT NULL,
    email           VARCHAR(255) NOT NULL,
    last_login      TIMESTAMP,
    last_ip         VARCHAR(255),
    registration_ip VARCHAR(255),
    application_id  VARCHAR(255),
    foreign key (application_id)
        references applications (application_id)
);

CREATE TABLE IF NOT EXISTS sessions
(
    session_id VARCHAR(255) PRIMARY KEY,
    user_id    VARCHAR(255),
    foreign key (user_id)
        references users (user_id)
);

CREATE TABLE IF NOT EXISTS admin_sessions
(
    session_id VARCHAR(255) PRIMARY KEY,
    admin_id   VARCHAR(255),
    foreign key (admin_id)
        references admins (admin_id)
);

CREATE TABLE IF NOT EXISTS license_keys
(
    license_key_id VARCHAR(255) PRIMARY KEY,
    application_id VARCHAR(255),
    foreign key (application_id)
        references applications (application_id)
);
