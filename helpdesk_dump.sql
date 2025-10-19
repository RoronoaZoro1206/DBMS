SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Drop tables to ensure a clean slate
--
DROP TABLE IF EXISTS tickets;
DROP TABLE IF EXISTS students;
DROP TABLE IF EXISTS staff_users;

--
--
CREATE TABLE public.staff_users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin_role','support_role'))
);

CREATE TABLE public.students (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT
);

CREATE TABLE public.tickets (
    id SERIAL PRIMARY KEY,
    student_id INT NOT NULL REFERENCES public.students(id),
    issue TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

--
--
INSERT INTO public.staff_users (username, password, role) VALUES
('admin', 'adminpass123', 'admin_role'),
('support_staff', 'supportpass', 'support_role'),
('it_support', 'itsupportpass', 'support_role');

INSERT INTO public.students (name, email, phone) VALUES
('Juan Dela Cruz', 'juan.delacruz@ctu.edu.ph', '555-1234'),
('Pedro Macaraig', 'pedro.macaraig@ctu.edu.ph', '555-5678'),
('Maria Dizcaya', 'maria.dizcaya@ctu.edu.ph', '555-9012');

INSERT INTO public.tickets (student_id, issue) VALUES
(1, 'Cannot login to online portal.'),
(2, 'Laptop won''t connect to CTU Free WiFi.'),
(1, 'Password reset request.'),
(3, 'CTU account phone number is no longer active.');
