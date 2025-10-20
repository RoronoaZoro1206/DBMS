BEGIN;


-- 1. Clean up prior objects 
DROP VIEW IF EXISTS v_students_support;

-- 2. Restricted view: excludes sensitive phone column
--    Support staff will ONLY see this view (NOT the base students table)
CREATE OR REPLACE VIEW v_students_support AS
SELECT 
    s.id, 
    s.name, 
    s.email,
    CASE
        WHEN pg_has_role (current_user, 'support_role', 'member') 
            THEN 'RESTRICTED'
        ELSE s.phone
    END as phone
FROM public.students s
ORDER BY s.id;

COMMENT ON VIEW v_students_support IS
'Restricted student directory for support staff; phone excluded (Least Privilege).';


-- 3. Create group (NOLOGIN) roles 
--    Group roles: support_role, admin_role, student_role
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'support_role') THEN
        CREATE ROLE support_role NOLOGIN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admin_role') THEN
        CREATE ROLE admin_role NOLOGIN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'student_role') THEN
        CREATE ROLE student_role NOLOGIN;
    END IF;
END$$;

-- 4. Revoke broad defaults from PUBLIC (all future/ existing objects)
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

-- 5. Minimal schema access: all roles need USAGE to reach objects
GRANT USAGE ON SCHEMA public TO support_role, admin_role, student_role;

-- 6. Admin role gets full DML + sequence privileges (can search & manage)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO admin_role;
GRANT ALL PRIVILEGES                 ON ALL SEQUENCES IN SCHEMA public TO admin_role;

-- 7. Limited contributors: support/student roles can only submit tickets (no direct reads).
REVOKE ALL ON public.tickets FROM support_role, student_role;
GRANT INSERT ON public.tickets TO support_role, student_role;

-- Allow ticket id generation (SERIAL / identity) via its sequence only.
GRANT USAGE ON SEQUENCE public.tickets_id_seq TO support_role, student_role;

-- Allow foreign key referencing students.id without exposing table data.
GRANT REFERENCES (id) ON public.students TO support_role, student_role;

-- Provide read access ONLY to the restricted view (no phone column) for support staff.
GRANT SELECT ON v_students_support TO support_role;

-- Ensure no direct access to underlying sensitive base tables.
REVOKE ALL ON public.students   FROM support_role, student_role;
REVOKE ALL ON public.staff_users FROM support_role, student_role;

---------------------------------------------------------------------------
-- 8. Future-proofing: default privileges
--    Prevent accidental leakage to PUBLIC; explicitly grant admin control.
---------------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES    FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO admin_role;
ALTER DEFAULT PRIVILEGES GRANT ALL ON SEQUENCES TO admin_role;

---------------------------------------------------------------------------
-- 9. Normalize textual role values stored in application table staff_users
--    (Ensures consistency with new RBAC scheme)
---------------------------------------------------------------------------
UPDATE public.staff_users
SET role = CASE
             WHEN role IN ('admin','admin_role') THEN 'admin_role'
                         WHEN role IN ('student','student_role') THEN 'student_role'
             ELSE 'support_role'
           END;

COMMIT;


-- Manual privilege checks (optional; run as superuser for verification)
-- SET ROLE support_role;
-- SELECT * FROM v_students_support;
-- SELECT * FROM tickets;
-- INSERT INTO tickets (student_id, issue) VALUES (1, 'Cannot access the student portal.');
-- RESET ROLE;

-- SET ROLE student_role;
-- INSERT INTO tickets (student_id, issue) VALUES (1, 'Wifi connectivity issue.');
-- SELECT * FROM tickets; -- expected to fail (no SELECT privilege)
-- RESET ROLE;

-- SET ROLE admin_role;
-- SELECT * FROM v_students_support;
-- SELECT * FROM students;
-- SELECT * FROM audit_log_ticket;
-- RESET ROLE;

TRUNCATE TABLE public.audit_log_ticket RESTART IDENTITY CASCADE;
TRUNCATE TABLE public.tickets          RESTART IDENTITY CASCADE;