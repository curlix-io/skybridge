CREATE TABLE IF NOT EXISTS customers (
    id INT PRIMARY KEY,
    employee_id VARCHAR(32),
    name VARCHAR(64),
    email VARCHAR(128),
    ssn VARCHAR(32),
    notes TEXT,
    metadata TEXT
);

INSERT INTO customers (id, employee_id, name, email, ssn, notes, metadata) VALUES
    (1, 'EMP-4471', 'Alice Smith', 'alice@example.com', '123-45-6789', 'Called about billing, callback 555-867-5309', NULL),
    (2, 'EMP-8823', 'Bob Jones',   'bob@example.com',   '987-65-4321', 'VIP customer, no issues reported', NULL),
    (3, 'EMP-1092', 'Carol White', 'carol@example.com', '456-78-9123', 'Escalated ticket, no callback needed',
     '{"contact":{"phone":"555-201-3344"},"note":"call back"}');
