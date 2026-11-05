-- ============================================================
-- FIELDTRACK — Emails automáticos (2026-11-04)
-- Ver: sessions/inventory-tracker/_estado.md
--
-- Dispara emails transaccionais (via Resend, chamado pela Edge
-- Function send-email) directamente de triggers na BD, não de código
-- disperso em cada fluxo cliente — assim funciona seja qual for o
-- caminho que mudou a linha (webhook Paddle, conversão manual no
-- admin, uma correcção via SQL directo, etc).
-- ============================================================

create extension if not exists pg_net;
create extension if not exists pg_cron;

-- ──────────────────────────────────────────────────────────
-- 1. Segredo partilhado entre o Postgres (triggers) e a Edge Function
-- send-email, para esta nunca aceitar chamadas que não venham de nós.
-- O MESMO valor tem de ser configurado como secret da função
-- (INTERNAL_SECRET) — ver instruções no chat.
-- ──────────────────────────────────────────────────────────
select vault.create_secret(encode(gen_random_bytes(24), 'hex'), 'internal_secret')
where not exists (select 1 from vault.decrypted_secrets where name = 'internal_secret');

-- ──────────────────────────────────────────────────────────
-- 2. Dados novos necessários
-- ──────────────────────────────────────────────────────────
alter table public.tenant_invites add column if not exists email text;
alter table public.tenants add column if not exists trial_reminders_sent smallint[] not null default '{}';

-- Devolve o email de contacto de um tenant: billing_email se
-- existir, senão o email do primeiro admin desse tenant (auth.users
-- não é exposto via API normal — só esta função, service_role-only,
-- consegue lê-lo).
create or replace function public.get_tenant_contact_email(p_tenant_id uuid)
returns text
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_email text;
begin
  select billing_email into v_email from public.tenants where id = p_tenant_id and billing_email is not null and billing_email != '';
  if v_email is not null then return v_email; end if;

  select u.email into v_email
  from public.profiles p
  join auth.users u on u.id = p.id
  where p.tenant_id = p_tenant_id and p.role = 'admin'
  order by p.created_at asc
  limit 1;
  return v_email;
end;
$$;

revoke all on function public.get_tenant_contact_email(uuid) from public, anon, authenticated;
grant execute on function public.get_tenant_contact_email(uuid) to service_role;

-- ──────────────────────────────────────────────────────────
-- 3. Disparo genérico: chama a Edge Function send-email de forma
-- assíncrona (pg_net.http_post não bloqueia a transacção).
-- ──────────────────────────────────────────────────────────
create or replace function public.notify_email(p_event text, p_payload jsonb)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_secret text;
  v_url text := current_setting('app.settings.send_email_url', true);
begin
  select decrypted_secret into v_secret from vault.decrypted_secrets where name = 'internal_secret';
  if v_secret is null then
    raise warning 'notify_email: internal_secret not configured, skipping % ', p_event;
    return;
  end if;
  if v_url is null or v_url = '' then
    v_url := 'https://cqpsofmaaktsjtlkariw.supabase.co/functions/v1/send-email';
  end if;

  perform net.http_post(
    url := v_url,
    headers := jsonb_build_object('Content-Type', 'application/json', 'x-internal-secret', v_secret),
    body := jsonb_build_object('event', p_event, 'payload', p_payload)
  );
exception when others then
  -- Um email falhado nunca deve reverter a transacção de negócio que o disparou.
  raise warning 'notify_email: failed to send % — %', p_event, sqlerrm;
end;
$$;

-- ──────────────────────────────────────────────────────────
-- 4. Triggers
-- ──────────────────────────────────────────────────────────

-- Boas-vindas ao criar um tenant novo (trial ou pendente de pagamento).
create or replace function public.trg_tenant_welcome()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.is_trial then
    perform public.notify_email('welcome_trial', jsonb_build_object('tenant_id', new.id));
  elsif new.subscription_status = 'pending' then
    perform public.notify_email('welcome_pending', jsonb_build_object('tenant_id', new.id));
  end if;
  return new;
end;
$$;

drop trigger if exists tenant_welcome_email on public.tenants;
create trigger tenant_welcome_email
  after insert on public.tenants
  for each row execute function public.trg_tenant_welcome();

-- Mudanças de estado de subscrição (activada / atraso / cancelada).
create or replace function public.trg_tenant_subscription_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.subscription_status is distinct from old.subscription_status then
    if new.subscription_status = 'active' then
      perform public.notify_email('payment_confirmed', jsonb_build_object('tenant_id', new.id));
    elsif new.subscription_status = 'past_due' then
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

drop trigger if exists tenant_subscription_email on public.tenants;
create trigger tenant_subscription_email
  after update on public.tenants
  for each row execute function public.trg_tenant_subscription_email();

-- Pagamento falhado (transaction.payment_failed do Paddle).
create or replace function public.trg_payment_failed_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status = 'failed' then
    perform public.notify_email('payment_failed', jsonb_build_object('tenant_id', new.tenant_id));
  end if;
  return new;
end;
$$;

drop trigger if exists payment_failed_email on public.payments;
create trigger payment_failed_email
  after insert on public.payments
  for each row execute function public.trg_payment_failed_email();

-- Convite com email associado (quando o admin preenche o email do
-- convidado em vez de só copiar o link).
create or replace function public.trg_invite_email()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.email is not null and new.email != '' then
    perform public.notify_email('invite', jsonb_build_object(
      'tenant_id', new.tenant_id, 'token', new.token, 'role', new.role, 'email', new.email
    ));
  end if;
  return new;
end;
$$;

drop trigger if exists invite_email on public.tenant_invites;
create trigger invite_email
  after insert on public.tenant_invites
  for each row execute function public.trg_invite_email();

-- ──────────────────────────────────────────────────────────
-- 5. Avisos de trial a terminar (5, 2 e 1 dia antes) — cron diário,
-- porque isto depende do tempo a passar, não de uma linha a mudar.
-- ──────────────────────────────────────────────────────────
create or replace function public.send_trial_reminders()
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_tenant record;
  v_days_left int;
begin
  for v_tenant in
    select id, trial_ends_at, trial_reminders_sent
    from public.tenants
    where is_trial = true and active = true
      and trial_ends_at is not null
      and trial_ends_at > now()
      and trial_ends_at <= now() + interval '5 days'
  loop
    v_days_left := ceil(extract(epoch from (v_tenant.trial_ends_at - now())) / 86400)::int;
    if v_days_left in (5, 2, 1) and not (v_days_left = any(v_tenant.trial_reminders_sent)) then
      perform public.notify_email('trial_reminder', jsonb_build_object('tenant_id', v_tenant.id, 'days_left', v_days_left));
      update public.tenants
      set trial_reminders_sent = array_append(trial_reminders_sent, v_days_left::smallint)
      where id = v_tenant.id;
    end if;
  end loop;
end;
$$;

revoke all on function public.send_trial_reminders() from public, anon, authenticated;
grant execute on function public.send_trial_reminders() to service_role, postgres;

select cron.unschedule(jobid) from cron.job where jobname = 'fieldtrack-trial-reminders';
select cron.schedule('fieldtrack-trial-reminders', '0 9 * * *', $$select public.send_trial_reminders();$$);

-- ──────────────────────────────────────────────────────────
-- 6. create_invite() passa a aceitar um email opcional — se
-- preenchido, o convite é enviado automaticamente (trigger acima);
-- se vazio, continua a funcionar como até agora (copiar o link à mão).
-- ──────────────────────────────────────────────────────────
drop function if exists public.create_invite(text, text[]);
create or replace function public.create_invite(
  p_role text default 'viewer',
  p_assigned_countries text[] default '{}',
  p_email text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_admin_tenant uuid;
  v_token uuid;
begin
  select tenant_id into v_admin_tenant from public.profiles where id = auth.uid() and role = 'admin';
  if v_admin_tenant is null then
    raise exception 'Only tenant admins can create invites.';
  end if;
  if p_role not in ('admin','supervisor','viewer') then
    raise exception 'Invalid role.';
  end if;

  insert into public.tenant_invites (tenant_id, role, assigned_countries, created_by, email)
  values (v_admin_tenant, p_role, coalesce(p_assigned_countries, '{}'), auth.uid(), p_email)
  returning token into v_token;

  return jsonb_build_object('token', v_token, 'expires_at', now() + interval '14 days');
end;
$$;

revoke all on function public.create_invite(text, text[], text) from public, anon;
grant execute on function public.create_invite(text, text[], text) to authenticated, service_role;
