
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
    
END;
$$;

-- Set permissions for the procedure
REVOKE UPDATE ON tickets FROM PUBLIC;
REVOKE EXECUTE ON PROCEDURE mark_ticket_resolved(INT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON PROCEDURE public.mark_ticket_resolved(INT,TEXT) TO admin_role;
REVOKE EXECUTE ON PROCEDURE mark_ticket_resolved(INT,TEXT) FROM support_role;

-- ============================================================================
-- PART 2: Audit Log Trigger Function (NO ticket_id column!)
-- ============================================================================

CREATE OR REPLACE FUNCTION log_ticket_changes()
RETURNS TRIGGER AS $$ 
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
        -- NO ticket_id - just student_id, issue, created_at
        INSERT INTO audit_log(
            action,
            staff_id, 
            old_data,
            new_data)
        VALUES (
            'INSERT',
            v_user_id,
            NULL,
            jsonb_build_object(
                'student_id', NEW.student_id,
                'issue', NEW.issue,
                'created_at', NEW.created_at
            )
        );
        RETURN NEW;

    ELSIF TG_OP = 'UPDATE' THEN
        -- NO ticket_id
        INSERT INTO audit_log(
            action,
            staff_id, 
            old_data,
            new_data)
        VALUES (
            'UPDATE',
            v_user_id,
            jsonb_build_object(
                'student_id', OLD.student_id,
                'issue', OLD.issue,
                'created_at', OLD.created_at
            ),
            jsonb_build_object(
                'student_id', NEW.student_id,
                'issue', NEW.issue,
                'created_at', NEW.created_at
            )
        );
        RETURN NEW;

    ELSIF TG_OP = 'DELETE' THEN
        -- NO ticket_id
        INSERT INTO audit_log(
            action,
            staff_id, 
            old_data,
            new_data)
        VALUES (
            'DELETE',
            v_user_id,
            jsonb_build_object(
                'student_id', OLD.student_id,
                'issue', OLD.issue,
                'created_at', OLD.created_at
            ),
            NULL
        );
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PART 3: Database Configuration
-- ============================================================================

-- Modify the audit_log table to allow NULL staff_id
ALTER TABLE audit_log 
ALTER COLUMN staff_id DROP NOT NULL;

-- ============================================================================
-- PART 4: Create ONLY ONE Trigger (NO DUPLICATES!)
-- ============================================================================

-- Drop any existing audit triggers first (safety measure)
DROP TRIGGER IF EXISTS audit_ticket_trigger ON tickets;
DROP TRIGGER IF EXISTS trg_audit_tickets ON tickets;

-- Create ONLY ONE trigger
CREATE TRIGGER trg_audit_tickets
AFTER INSERT OR UPDATE OR DELETE ON tickets
FOR EACH ROW
EXECUTE FUNCTION log_ticket_changes();

-- ============================================================================
-- PART 5: RBAC Permissions for Audit Log
-- ============================================================================

REVOKE ALL ON TABLE public.audit_log FROM PUBLIC;
REVOKE ALL ON TABLE public.audit_log FROM admin_role;
REVOKE ALL ON TABLE public.audit_log FROM support_role;

-- Step 3: Grant full permissions to admin_role
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.audit_log TO admin_role;

-- Step 4: Grant INSERT only to support_role  
GRANT INSERT ON TABLE public.audit_log TO support_role;

-- ============================================================================
-- PART 6: RBAC Permissions for Tickets
-- ============================================================================

-- Admin can update all columns in tickets table
GRANT UPDATE ON TABLE public.tickets TO admin_role;

-- ============================================================================
-- PART 7: Helper Function (Get All Tickets)
-- ============================================================================

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

-- ============================================================================
-- PART 8: Verification Queries
-- ============================================================================

-- Check all triggers on tickets table (should see 3 total: 2 FK constraints + 1 audit)
SELECT 
    '✅ TRIGGERS ON TICKETS TABLE:' as info;

SELECT 
    tgname as trigger_name,
    CASE 
        WHEN tgname LIKE 'RI_%' OR tgname LIKE 'Constraint%' THEN '🔒 FK Constraint'
        WHEN tgname = 'trg_audit_tickets' THEN '📝 Audit Logger'
        ELSE '❓ Unknown'
    END as purpose,
    CASE 
        WHEN tgenabled = 'O' THEN '✅ Enabled'
        ELSE '❌ Disabled'
    END as status
FROM pg_trigger 
WHERE tgrelid = 'tickets'::regclass
ORDER BY tgname;

-- Count total triggers (should be 3: 2 FK + 1 audit)
SELECT 
    COUNT(*) as total_triggers,
    '(Expected: 3 = 2 FK constraints + 1 audit trigger)' as note
FROM pg_trigger 
WHERE tgrelid = 'tickets'::regclass;

-- Check audit_log structure
SELECT 
    '✅ AUDIT_LOG TABLE STRUCTURE:' as info;

SELECT 
    column_name, 
    data_type, 
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'audit_log' 
ORDER BY ordinal_position;

-- View current data
SELECT '✅ CURRENT DATA:' as info;
SELECT * FROM tickets;
SELECT * FROM audit_log ORDER BY audit_id DESC;
SELECT * FROM staff_users;

-- ============================================================================
-- PART 9: Test Script (Optional - Uncomment to Test)
-- ============================================================================

-- Set staff_id for auditing
-- SET session "app.user_id" = 1;

-- Test INSERT (should create 1 audit entry)
-- INSERT INTO tickets (student_id, issue) VALUES (1, 'Test INSERT - should create ONLY 1 audit entry');

-- Test UPDATE (should create 1 audit entry)
-- UPDATE tickets SET student_id = 2 WHERE id = 3;

-- Test DELETE (should create 1 audit entry)
-- DELETE FROM tickets WHERE id = 6;

-- Verify audit log (each operation should have ONLY 1 entry)
-- SELECT 
--     audit_id,
--     action,
--     staff_id,
--     new_data->>'student_id' as student_id,
--     new_data->>'issue' as issue,
--     logged_at
-- FROM audit_log
-- ORDER BY audit_id DESC
-- LIMIT 10;
