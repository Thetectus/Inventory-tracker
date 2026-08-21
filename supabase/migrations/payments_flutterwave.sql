-- ============================================================
-- FIELDTRACK — Self-serve paid subscription (Flutterwave)
-- The Tectus · Agosto 2026
--
-- Depende de:
--   - tenants.subscription_status (já criado — ver
--     sessions/inventory-tracker/2026-08-20-auditoria-bugs.md no vault)
--   - tabelas subscriptions / payments (já criadas, idem)
--
-- Correr no Supabase SQL Editor (idempotente).
-- ============================================================

-- ──────────────────────────────────────────────────────────
-- 1. create_pending_tenant()
-- Chamada por subscribe.html via RPC (anon key). Cria o tenant
-- em estado "pending" (active=false) — fica inactivo até o
-- webhook do Flutterwave confirmar o pagamento.
-- ──────────────────────────────────────────────────────────
create or replace function public.create_pending_tenant(
  p_name      text,
  p_slug      text,
  p_email     text,
  p_user_id   uuid,
  p_full_name text,
  p_plan      text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_tenant_id      uuid;
  v_max_users      int;
  v_max_locations  int;
begin
  case p_plan
    when 'starter'      then v_max_users := 5;   v_max_locations := 3;
    when 'professional' then v_max_users := 15;  v_max_locations := 10;
    when 'enterprise'   then v_max_users := 999; v_max_locations := 999;
    else raise exception 'Invalid plan: %', p_plan;
  end case;

  insert into public.tenants (
    name, slug, plan, max_users, max_locations,
    billing_email, active, is_trial, subscription_status
  ) values (
    p_name, p_slug, p_plan, v_max_users, v_max_locations,
    p_email, false, false, 'pending'
  ) returning id into v_tenant_id;

  update public.profiles
  set tenant_id = v_tenant_id, role = 'admin'
  where id = p_user_id;

  return jsonb_build_object('tenant_id', v_tenant_id);
end;
$$;

revoke all on function public.create_pending_tenant(text,text,text,uuid,text,text) from public;
grant execute on function public.create_pending_tenant(text,text,text,uuid,text,text) to anon, authenticated;


-- ──────────────────────────────────────────────────────────
-- 2. get_tenant_activation_status()
-- Chamada por subscribe-success.html (polling, anon key) para
-- saber se o pagamento já foi confirmado. Devolve só o mínimo
-- necessário — não expõe billing_email nem outros dados.
-- ──────────────────────────────────────────────────────────
create or replace function public.get_tenant_activation_status(p_tenant_id uuid)
returns jsonb
language sql
stable
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'active', active,
    'subscription_status', subscription_status
  )
  from public.tenants
  where id = p_tenant_id;
$$;

revoke all on function public.get_tenant_activation_status(uuid) from public;
grant execute on function public.get_tenant_activation_status(uuid) to anon, authenticated;


-- ──────────────────────────────────────────────────────────
-- 3. activate_paid_subscription()
-- Chamada APENAS pela Edge Function flutterwave-webhook, com a
-- service_role key — depois de essa function já ter re-verificado
-- o pagamento directamente na API do Flutterwave (nunca confia só
-- no corpo do webhook). Por isso só é concedida a service_role.
-- ──────────────────────────────────────────────────────────
create or replace function public.activate_paid_subscription(
  p_tenant_id  uuid,
  p_plan       text,
  p_amount     numeric,
  p_currency   text,
  p_reference  text,
  p_flw_tx_id  text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_sub_id bigint;
begin
  update public.tenants
  set active = true,
      is_trial = false,
      plan = p_plan,
      subscription_status = 'active'
  where id = p_tenant_id;

  insert into public.subscriptions (tenant_id, plan, status, amount, currency, payment_method)
  values (p_tenant_id, p_plan, 'active', p_amount, p_currency, 'flutterwave')
  returning id into v_sub_id;

  insert into public.payments (tenant_id, subscription_id, amount, currency, reference, method, status, notes)
  values (p_tenant_id, v_sub_id, p_amount, p_currency, p_reference, 'flutterwave', 'confirmed', 'Flutterwave tx ' || p_flw_tx_id);
end;
$$;

revoke all on function public.activate_paid_subscription(uuid,text,numeric,text,text,text) from public;
grant execute on function public.activate_paid_subscription(uuid,text,numeric,text,text,text) to service_role;


-- ──────────────────────────────────────────────────────────
-- 4. Verificação
-- ──────────────────────────────────────────────────────────
select routine_name, security_type
from information_schema.routines
where routine_schema = 'public'
  and routine_name in ('create_pending_tenant','get_tenant_activation_status','activate_paid_subscription');
