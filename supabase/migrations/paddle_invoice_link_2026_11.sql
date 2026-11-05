-- ============================================================
-- FIELDTRACK — Link para o recibo oficial da Paddle no email (2026-11-05)
-- Kiko perguntou se o recibo real da Paddle é anexado — não era.
-- Adiciona o link do PDF oficial da Paddle (não um anexo, por agora)
-- ao email de "pagamento confirmado".
-- ============================================================

alter table public.payments add column if not exists invoice_url text;

-- activate_paid_subscription ganha um parâmetro opcional p_invoice_url,
-- guardado na mesma linha de payments inserida — importante que seja
-- no INSERT, não num UPDATE a seguir, porque o trigger do email é
-- AFTER INSERT e só vê o que está na linha nesse momento.
create or replace function public.activate_paid_subscription(
  p_tenant_id      uuid,
  p_plan           text,
  p_amount         numeric,
  p_currency       text,
  p_reference      text,
  p_provider_tx_id text,
  p_method         text default 'paddle',
  p_invoice_url    text default null
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

  insert into public.payments (tenant_id, subscription_id, amount, currency, reference, method, status, notes, invoice_url)
  values (p_tenant_id, v_sub_id, p_amount, p_currency, p_reference, p_method, 'confirmed', initcap(p_method) || ' tx ' || p_provider_tx_id, p_invoice_url);
end;
$$;

drop function if exists public.activate_paid_subscription(uuid,text,numeric,text,text,text,text);
revoke all on function public.activate_paid_subscription(uuid,text,numeric,text,text,text,text,text) from public, anon, authenticated;
grant execute on function public.activate_paid_subscription(uuid,text,numeric,text,text,text,text,text) to service_role;

-- trg_payment_confirmed_email passa a incluir o invoice_url no payload.
create or replace function public.trg_payment_confirmed_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status = 'confirmed' then
    perform public.notify_email('payment_confirmed', jsonb_build_object(
      'tenant_id', new.tenant_id,
      'amount', new.amount,
      'currency', new.currency,
      'method', new.method,
      'reference', new.reference,
      'paid_at', new.paid_at,
      'invoice_url', new.invoice_url
    ));
  end if;
  return new;
end;
$$;
