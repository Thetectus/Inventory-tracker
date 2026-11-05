-- ============================================================
-- FIELDTRACK — Dunning: tratar falhas de renovação/cancelamento (2026-11-04)
-- Ver: sessions/inventory-tracker/_estado.md
--
-- O paddle-webhook só tratava transaction.completed. Os outros 3
-- eventos já seleccionados no destino de notificações da Paddle
-- (subscription.canceled, subscription.past_due,
-- transaction.payment_failed) eram recebidos mas ignorados. Este
-- ficheiro adiciona o tratamento correspondente.
-- ============================================================

-- 'past_due' é um estado novo: a Paddle entra em dunning automático
-- (retries durante ~2 semanas) antes de cancelar de facto — mantemos
-- o tenant activo durante esse período (não bloquear acesso por uma
-- falha de cartão que pode resolver-se sozinha), só registamos o
-- estado para aparecer no admin.
alter table public.tenants drop constraint if exists tenants_subscription_status_check;
alter table public.tenants add constraint tenants_subscription_status_check
  check (subscription_status in ('pending','trial','active','past_due','expired','suspended','cancelled'));

-- Regista uma falha de pagamento (transaction.payment_failed) sem
-- alterar o estado do tenant — é só para aparecer no histórico do
-- admin; a Paddle vai tentar novamente automaticamente.
create or replace function public.record_failed_payment(
  p_tenant_id uuid,
  p_amount numeric,
  p_currency text,
  p_reference text,
  p_provider_tx_id text,
  p_method text default 'paddle'
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.payments (tenant_id, amount, currency, reference, method, status, notes)
  values (p_tenant_id, p_amount, p_currency, p_reference, p_method, 'failed',
          initcap(p_method) || ' tx ' || p_provider_tx_id || ' failed');
end;
$$;

-- Actualiza o estado de subscrição por causa de um evento de
-- dunning/cancelamento da Paddle. 'past_due' mantém o acesso activo
-- (grace period); 'cancelled' bloqueia o acesso como qualquer outro
-- tenant suspenso.
create or replace function public.set_subscription_status(
  p_tenant_id uuid,
  p_status text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_status not in ('past_due', 'cancelled') then
    raise exception 'set_subscription_status: unsupported status %', p_status;
  end if;

  update public.tenants
  set subscription_status = p_status,
      active = case when p_status = 'cancelled' then false else active end
  where id = p_tenant_id;
end;
$$;

revoke all on function public.record_failed_payment(uuid,numeric,text,text,text,text) from public, anon, authenticated;
grant execute on function public.record_failed_payment(uuid,numeric,text,text,text,text) to service_role;
revoke all on function public.set_subscription_status(uuid,text) from public, anon, authenticated;
grant execute on function public.set_subscription_status(uuid,text) to service_role;
