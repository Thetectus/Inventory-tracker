-- ============================================================
-- FIELDTRACK — Fix: 'pending' em falta no CHECK de subscription_status
-- The Tectus · Agosto 2026
--
-- Bug: create_pending_tenant() (payments_flutterwave.sql) insere
-- subscription_status='pending', mas a constraint original só
-- permitia ('trial','active','expired','suspended','cancelled') —
-- descoberto ao testar /subscribe no sandbox Paddle:
-- "new row for relation tenants violates check constraint
--  tenants_subscription_status_check"
-- ============================================================

alter table public.tenants drop constraint if exists tenants_subscription_status_check;
alter table public.tenants add constraint tenants_subscription_status_check
  check (subscription_status in ('pending','trial','active','expired','suspended','cancelled'));
