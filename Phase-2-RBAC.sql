BEGIN;

-- 1. Clean up prior objects 
DROP VIEW IF EXISTS v_students_support CASCADE;

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
--    Group roles: support_role, admin_role
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'support_role') THEN
        CREATE ROLE support_role NOLOGIN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admin_role') THEN
        CREATE ROLE admin_role NOLOGIN;
    END IF;
END$$;

-- 4. Revoke broad defaults from PUBLIC (all future/ existing objects)
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

-- 5. Minimal schema access: both roles need USAGE to reach objects
GRANT USAGE ON SCHEMA public TO support_role, admin_role;

-- 6. ADMIN_ROLE PERMISSIONS (Full Management Access)

-- Admin gets full DML on all tables
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO admin_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO admin_role;

COMMENT ON ROLE admin_role IS 
'Administrator role with full access to:
- View, search, create, update, delete tickets
- View, add students (including phone numbers)  
- Create staff accounts
- View audit logs
- Mark tickets as resolved';


-- 7. SUPPORT_ROLE PERMISSIONS (Limited Ticket Creation Only)

-- 7a. Tickets: INSERT only (cannot SELECT, UPDATE, DELETE)
REVOKE ALL ON public.tickets FROM support_role;
GRANT INSERT ON public.tickets TO support_role;

-- Allow ticket id generation (SERIAL / identity) via its sequence only
GRANT USAGE ON SEQUENCE public.tickets_id_seq TO support_role;

-- 7b. Students: NO direct access (uses restricted view instead)
REVOKE ALL ON public.students FROM support_role;

-- Allow foreign key referencing students.id without exposing table data
GRANT REFERENCES (id) ON public.students TO support_role;

-- Provide read access ONLY to the restricted view (no phone column)
GRANT SELECT ON v_students_support TO support_role;

-- 7c. Staff Users: NO access (cannot view or manage accounts)
REVOKE ALL ON public.staff_users FROM support_role;

-- 7d. Audit Log: Explicit permissions for both roles
REVOKE ALL ON TABLE public.audit_log FROM PUBLIC;
REVOKE ALL ON TABLE public.audit_log FROM admin_role;
REVOKE ALL ON TABLE public.audit_log FROM support_role;

-- Grant full permissions to admin_role
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.audit_log TO admin_role;

-- Grant INSERT only to support_role (for triggers)
GRANT INSERT ON TABLE public.audit_log TO support_role;

-- 8. Future-proofing: default privileges
--    Prevent accidental leakage to PUBLIC; explicitly grant admin control.

ALTER DEFAULT PRIVILEGES REVOKE ALL ON TABLES    FROM PUBLIC;
ALTER DEFAULT PRIVILEGES REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO admin_role;
ALTER DEFAULT PRIVILEGES GRANT ALL ON SEQUENCES TO admin_role;

-- 9. Normalize textual role values stored in application table staff_users
--     (Ensures consistency with new RBAC scheme)

UPDATE public.staff_users
SET role = CASE
             WHEN role IN ('admin','admin_role') THEN 'admin_role'
             ELSE 'support_role'
           END;

COMMIT;

-- Reset to superuser for setup
RESET ROLE;

---------------------------------------------------------------------------
-- TEST 1: SUPPORT_ROLE PERMISSIONS
---------------------------------------------------------------------------
SET ROLE support_role;

-- ✓ SHOULD SUCCEED: View student directory (restricted - no phone)
SELECT * FROM v_students_support;

-- ✓ SHOULD SUCCEED: Create new ticket
INSERT INTO tickets (student_id, issue) 
VALUES (1, 'Test ticket from support role - cannot login to portal');

-- ✗ SHOULD FAIL: Cannot view tickets (no SELECT permission)
-- Expected: ERROR: permission denied for table tickets
SELECT * FROM tickets;

-- ✗ SHOULD FAIL: Cannot search/filter tickets
SELECT * FROM tickets WHERE issue ILIKE '%portal%';

-- ✗ SHOULD FAIL: Cannot update tickets
UPDATE tickets SET issue = 'Updated issue' WHERE id = 1;

-- ✗ SHOULD FAIL: Cannot delete tickets
DELETE FROM tickets WHERE id = 1;

-- ✗ SHOULD FAIL: Cannot view full student data (with phone)
SELECT * FROM students;

-- ✗ SHOULD FAIL: Cannot add students
INSERT INTO students (name, email, phone) 
VALUES ('Test Student', 'test@ctu.edu.ph', '555-0000');

-- ✗ SHOULD FAIL: Cannot view staff accounts
SELECT * FROM staff_users;

-- ✗ SHOULD FAIL: Cannot view audit logs
SELECT * FROM audit_log;

-- Reset role
RESET ROLE;

-- TEST 2: ADMIN_ROLE PERMISSIONS
SET ROLE admin_role;

-- ✓ SHOULD SUCCEED: View student directory
SELECT * FROM v_students_support;

-- ✓ SHOULD SUCCEED: View full student data (including phone)
SELECT * FROM students;

-- ✓ SHOULD SUCCEED: Add new student
INSERT INTO students (name, email, phone) 
VALUES ('Admin Test Student', 'admintest@ctu.edu.ph', '555-9999');

-- ✓ SHOULD SUCCEED: Create ticket
INSERT INTO tickets (student_id, issue) 
VALUES (1, 'Test ticket from admin - requesting email update');

-- ✓ SHOULD SUCCEED: View all tickets (search capability)
SELECT * FROM tickets;

-- ✓ SHOULD SUCCEED: Search tickets by keyword
SELECT * FROM tickets WHERE issue ILIKE '%email%';

-- ✓ SHOULD SUCCEED: View resolved tickets
SELECT * FROM tickets WHERE issue LIKE '%[Resolved by admin%';

-- ✓ SHOULD SUCCEED: Update ticket
UPDATE tickets 
SET issue = 'Updated by admin - email change completed' 
WHERE student_id = 1;

-- ✓ SHOULD SUCCEED: Mark ticket as resolved (update)
UPDATE tickets 
SET issue = issue || ' [Resolved by admin admin on ' || NOW() || ']'
WHERE id = (SELECT MAX(id) FROM tickets);

-- ✓ SHOULD SUCCEED: Delete ticket
DELETE FROM tickets WHERE id = (SELECT MAX(id) FROM tickets);

-- ✓ SHOULD SUCCEED: View staff accounts
SELECT id, username, role FROM staff_users;

-- ✓ SHOULD SUCCEED: View audit logs
SELECT * FROM audit_log ORDER BY logged_at DESC LIMIT 10;

-- ✓ SHOULD SUCCEED: Create staff account (via INSERT)
-- Note: In helpdesk.py, admin uses bcrypt for password hashing
-- This is a simplified version for testing
INSERT INTO staff_users (username, password_hash, role)
VALUES ('test_support', 'temp_hash', 'support_role');

-- Reset role
RESET ROLE;

-- TEST 3: PERMISSION VERIFICATION QUERIES

-- View all grants for support_role
SELECT 
    grantee,
    table_schema,
    table_name,
    privilege_type
FROM information_schema.table_privileges
WHERE grantee = 'support_role'
ORDER BY table_name, privilege_type;

-- View all grants for admin_role
SELECT 
    grantee,
    table_schema,
    table_name,
    privilege_type
FROM information_schema.table_privileges
WHERE grantee = 'admin_role'
ORDER BY table_name, privilege_type;

TRUNCATE TABLE public.audit_log RESTART IDENTITY CASCADE;
TRUNCATE TABLE public.tickets          RESTART IDENTITY CASCADE;