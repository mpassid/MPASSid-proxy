CREATE TABLE mpass_services (
    id BIGINT AUTO_INCREMENT NOT NULL,
    samlEntityId VARCHAR(255) NOT NULL,
    samlAcsUrl VARCHAR(255) NOT NULL,
    startTime TIMESTAMP NOT NULL,
    endTime TIMESTAMP,
    PRIMARY KEY (id)
	);
