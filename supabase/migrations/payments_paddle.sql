-- ============================================================
-- FIELDTRACK — Pivot do checkout self-serve: Flutterwave → Paddle
-- The Tectus · Agosto 2026
--
-- Motivo: a Flutterwave só aceitou a Nigéria no registo real do
-- Kiko, apesar da documentação dizer que suportava Angola. Ver
-- sessions/inventory-tracker/2026-08-31-precos-e-paddle.md no vault.
--
-- Este ficheiro generaliza o que só suportava 'flutterwave' para
-- aceitar também 'paddle' (e mantém 'flutterwave'/'stripe'/'other'
-- para não partir nada que já exista). Correr no Supabase SQL Editor,
-- depois de payments_flutterwave.sql já ter sido aplicado.
-- ============================================================

-- ──────────────────────────────────────────────────────────
-- 1. Alargar os CHECK constraints de payment_method/method
-- ──────────────────────────────────────────────────────────
alter table public.subscriptions drop constraint if exists subscriptions_payment_method_check;
alter table public.subscriptions add constraint subscriptions_payment_method_check
  check (payment_method in ('bank_transfer','flutterwave','paddle','stripe','other'));

alter table public.payments drop constraint if exists payments_method_check;
alter table public.payments add constraint payments_method_check
  check (method in ('bank_transfer','flutterwave','paddle','stripe','other'));


-- ──────────────────────────────────────────────────────────
-- 2. activate_paid_subscription() — generalizada para aceitar
-- qualquer gateway (p_method), não só Flutterwave. Chamada pela
-- Edge Function paddle-webhook (e continua a poder ser chamada por
-- qualquer futuro webhook de outro gateway) com a service_role key.
-- ──────────────────────────────────────────────────────────
create or replace function public.activate_paid_subscription(
  p_tenant_id      uuid,
  p_plan           text,
  p_amount         numeric,
  p_currency       text,
  p_reference      text,
  p_provider_tx_id text,
  p_method         text default 'paddle'
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
  values (p_tenant_id, p_plan, 'active', p_amount, p_currency, p_method)
  returning id into v_sub_id;

  insert into public.payments (tenant_id, subscription_id, amount, currency, reference, method, status, notes)
  values (p_tenant_id, v_sub_id, p_amount, p_currency, p_reference, p_method, 'confirmed', initcap(p_method) || ' tx ' || p_provider_tx_id);
end;
$$;

-- Substitui a versão anterior (6 argumentos, só Flutterwave) — o
-- Postgres não permite CREATE OR REPLACE quando a assinatura muda de
-- número de argumentos, por isso a antiga fica órfã; removê-la:
drop function if exists public.activate_paid_subscription(uuid,text,numeric,text,text,text);

revoke all on function public.activate_paid_subscription(uuid,text,numeric,text,text,text,text) from public;
grant execute on function public.activate_paid_subscription(uuid,text,numeric,text,text,text,text) to service_role;


-- ──────────────────────────────────────────────────────────
-- 3. Verificação
-- ──────────────────────────────────────────────────────────
select conname, pg_get_constraintdef(oid)
from pg_constraint
where conrelid in ('public.subscriptions'::regclass, 'public.payments'::regclass)
  and contype = 'c';

select routine_name, security_type
from information_schema.routines
where routine_schema = 'public' and routine_name = 'activate_paid_subscription';
