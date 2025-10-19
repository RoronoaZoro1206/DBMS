SELECT * FROM STAFF_USERS
SELECT * FROM STUDENTS 
SELECT * FROM TICKETS

CREATE ROLE admi_role
CREATE ROLE support_role

CREATE OR REPLACE PROCEDURE mark_ticket_resolved(p_ticket_id INT, p_admin_username TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_role TEXT;
    v_ticket_exists BOOLEAN;
BEGIN
    -- Get the role of the user
    SELECT role INTO v_role FROM staff_users WHERE username = p_admin_username;

    -- Check if user exists
    IF v_role IS NULL THEN
        RAISE EXCEPTION 'User not found in staff_users.';
    END IF;

    -- Check if user has admin role
    IF v_role != 'admin_role' THEN
        RAISE EXCEPTION 'Access denied: Only admin_role can mark tickets as resolved.';
    END IF;

    -- Check if ticket exists
    SELECT EXISTS(SELECT 1 FROM tickets WHERE id = p_ticket_id) INTO v_ticket_exists;
    IF NOT v_ticket_exists THEN
        RAISE EXCEPTION 'Ticket ID does not exist.';
    END IF;

    -- Mark ticket as resolved (this UPDATE will trigger the audit log)
    UPDATE tickets 
    SET issue = issue || ' [Resolved by admin ' || p_admin_username || ' on ' || NOW()::TEXT || ']' 
    WHERE id = p_ticket_id;
    
    -- Removed RAISE NOTICE to avoid psycopg2 issues
    
END;
$$;

REVOKE UPDATE ON tickets FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE mark_ticket_resolved(INT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE public.mark_ticket_resolved(INT,TEXT) TO admin_role;
REVOKE EXECUTE ON PROCEDURE mark_ticket_resolved(INT,TEXT) FROM support_role;


CALL mark_ticket_resolved(1,'admin_role');
-- ERROR: Access denied: Only admin_role can mark tickets as resolved.
---------------------------------------------------------------------------------------------------
CREATE TABLE audit_log_ticket (
	audit_id SERIAL PRIMARY KEY,
	ticket_id INT NOT NULL,
	staff_id INT NOT NULL,
	action VARCHAR(50) NOT NULL,
	old_data jsonb,
	new_data jsonb,
	logged_at TIMESTAMP DEFAULT NOW(),
	FOREIGN KEY(staff_id) REFERENCES STAFF_USERS(id)
);

CREATE OR REPLACE FUNCTION log_ticket_changes()
RETURNS trigger AS $$ 
DECLARE
    v_user_id INT;
BEGIN 
    -- Try to get the user_id from session, use 1 as default if not set
    BEGIN
        v_user_id := current_setting('app.user_id', true)::INT;
    EXCEPTION WHEN OTHERS THEN
        -- Default to staff_id = 1 (admin) if session variable is not set
        v_user_id := 1;
    END;

    -- If still null, set to 1
    IF v_user_id IS NULL THEN
        v_user_id := 1;
    END IF;

    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log_ticket(
            ticket_id, 
            action,
            staff_id, 
            old_data,
            new_data)
        VALUES (
            NEW.id,
            'INSERT',
            v_user_id,
            NULL,
            to_jsonb(NEW));
        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO audit_log_ticket(
            ticket_id, 
            action,
            staff_id, 
            old_data,
            new_data)
        VALUES (
            NEW.id,
            'UPDATE',
            v_user_id,
            to_jsonb(OLD),
            to_jsonb(NEW));
        RETURN NEW;

    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_log_ticket(
            ticket_id, 
            action,
            staff_id, 
            old_data,
            new_data)
        VALUES (
            OLD.id,
            'DELETE',
            v_user_id,
            to_jsonb(OLD),
            NULL);
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;


-- Modify the audit_log_ticket table to allow NULL staff_id temporarily
ALTER TABLE audit_log_ticket 
ALTER COLUMN staff_id DROP NOT NULL;

CREATE TRIGGER audit_ticket_trigger
AFTER INSERT OR UPDATE OR DELETE ON tickets
FOR EACH ROW
EXECUTE FUNCTION log_ticket_changes();

REVOKE ALL ON audit_log_ticket FROM PUBLIC;
REVOKE ALL ON audit_log_ticket FROM admin_role;
REVOKE ALL ON audit_log_ticket FROM support_role;

-- Only allow INSERT (so triggers can write logs)
-- These would make the AUDIT_LOG_TICKET immutable
GRANT INSERT ON audit_log_ticket TO admin_role;
GRANT INSERT ON audit_log_ticket TO support_role;

-- Remove update privilege from all columns by default
REVOKE UPDATE ON tickets FROM admin_role;

-- Then grant update only on allowed columns (preventing updates on tickets id and created by)
GRANT UPDATE (issue, student_id) ON tickets TO admin_role;

-- Set staff_id for auditing (hardcoded, only for testing update and delete)
SET session "app.user_id" = 1;  -- references the STAFF_USERS table

-- UPDATE a ticket
UPDATE tickets
SET student_id = 2
WHERE id = 3;

-- DELETE a ticket
DELETE FROM tickets
WHERE id = 6;

SELECT * FROM TICKETS;
SELECT * FROM AUDIT_LOG_TICKET;

SELECT * FROM STAFF_USERS
SELECT * FROM V_ROLE
SELECT * FROM audit_log_ticket ORDER BY logged_at DESC;



SELECT 
    audit_id,
    ticket_id,
    staff_id,
    action,
    old_data->>'issue' as old_issue,
    new_data->>'issue' as new_issue,
    logged_at
FROM audit_log_ticket
ORDER BY logged_at DESC;



-- 1. Check if trigger exists and is enabled
SELECT * FROM pg_trigger WHERE tgname = 'audit_ticket_trigger';

-- 2. Check the current audit log (should show ticket #33 now)
SELECT * FROM audit_log_ticket ORDER BY logged_at DESC;

-- 3. Check if ticket #33 was actually updated
SELECT id, issue, created_at FROM tickets WHERE id = 33;

-- 4. Test if the session variable is working
SELECT current_setting('app.user_id', true);


-- Step 1: Drop the trigger if it exists (just to be safe)
DROP TRIGGER IF EXISTS audit_ticket_trigger ON tickets;

-- Step 2: Recreate the trigger
CREATE TRIGGER audit_ticket_trigger
AFTER INSERT OR UPDATE OR DELETE ON tickets
FOR EACH ROW
EXECUTE FUNCTION log_ticket_changes();

-- Check if trigger exists now
SELECT * FROM pg_trigger WHERE tgname = 'audit_ticket_trigger';


-- Check the current column definition
SELECT column_name, is_nullable, data_type 
FROM information_schema.columns 
WHERE table_name = 'audit_log_ticket' AND column_name = 'staff_id';

-- Make staff_id nullable
ALTER TABLE audit_log_ticket 
ALTER COLUMN staff_id DROP NOT NULL;

------------------------------------------------------------------- FUNCTION

CREATE OR REPLACE FUNCTION get_all_tickets() 
RETURNS TABLE(ticket_id INT, ticket_issue TEXT) 
LANGUAGE plpgsql 
AS $$ 
BEGIN 
	RETURN QUERY 
	SELECT id, issue 
	FROM public.tickets; 
END; 
$$; 


GRANT EXECUTE ON FUNCTION get_all_tickets() TO admin_role; 
REVOKE EXECUTE ON FUNCTION get_all_tickets() FROM support_role;


