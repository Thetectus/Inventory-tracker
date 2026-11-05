-- ============================================================
-- FIELDTRACK — Emails mais completos (recibo com dados reais) (2026-11-05)
-- Kiko: "achei a mensagem de email muito fria. sem recibo nem nada de
-- comprovante de dados de usuario e recibos de pagamento"
--
-- Os templates já foram reescritos na Edge Function send-email para
-- um tom mais pessoal + tabela de "recibo". Este ficheiro faz os
-- triggers passarem os dados que faltavam (valor, moeda, método,
-- referência, data, plano, data de fim do trial) em vez de só o
-- tenant_id.
-- ============================================================

-- payment_confirmed passa a disparar directamente do INSERT em
-- payments com status='confirmed' (onde já estão todos os dados do
-- "recibo"), não da mudança de tenants.subscription_status — assim
-- evitamos dois triggers a competir pelos mesmos dados.
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
      'paid_at', new.paid_at
    ));
  end if;
  return new;
end;
$$;

drop trigger if exists payment_confirmed_email on public.payments;
create trigger payment_confirmed_email
  after insert on public.payments
  for each row execute function public.trg_payment_confirmed_email();

-- payment_failed ganha os mesmos detalhes (valor, moeda) que já
-- estavam disponíveis mas não eram passados ao email.
create or replace function public.trg_payment_failed_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status = 'failed' then
    perform public.notify_email('payment_failed', jsonb_build_object(
      'tenant_id', new.tenant_id,
      'amount', new.amount,
      'currency', new.currency
    ));
  end if;
  return new;
end;
$$;

-- tenant_subscription_email perde o ramo 'active' (passou para o
-- trigger de payments acima, com mais detalhe) — mantém só
-- past_due/cancelled/expired.
create or replace function public.trg_tenant_subscription_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.subscription_status is distinct from old.subscription_status then
    if new.subscription_status = 'past_due' then
      perform public.notify_email('past_due', jsonb_build_object('tenant_id', new.id));
    elsif new.subscription_status = 'cancelled' then
      perform public.notify_email('cancelled', jsonb_build_object('tenant_id', new.id));
    elsif new.subscription_status = 'expired' then
      perform public.notify_email('trial_expired', jsonb_build_object('tenant_id', new.id));
    end if;
  end if;
  return new;
end;
$$;

-- welcome_trial/welcome_pending passam a incluir o plano e a data de
-- fim do trial, para o email mostrar um "resumo" dos dados em vez de
-- só um texto genérico.
create or replace function public.trg_tenant_welcome()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.is_trial then
    perform public.notify_email('welcome_trial', jsonb_build_object(
      'tenant_id', new.id, 'trial_ends_at', new.trial_ends_at
    ));
  elsif new.subscription_status = 'pending' then
    perform public.notify_email('welcome_pending', jsonb_build_object('tenant_id', new.id));
  end if;
  return new;
end;
$$;
