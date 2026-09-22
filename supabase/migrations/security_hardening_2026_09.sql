-- ============================================================
-- FIELDTRACK — Security hardening (2026-09-22)
-- Ver: sessions/inventory-tracker/2026-09-22-auditoria-seguranca.md
--
-- Auditoria completa encontrou 5 falhas exploráveis AGORA em
-- produção. Este ficheiro corrige as que se resolvem em SQL/RLS.
-- (a service_role key, exposta em admin/index.html num repo público,
-- já foi rodada manualmente no dashboard — fora do âmbito deste SQL.)
-- ============================================================

-- ──────────────────────────────────────────────────────────
-- 0. super_admins — lista de quem pode usar o painel /admin, agora
-- servido pela Edge Function admin-api (substitui o acesso directo
-- com a service_role key no browser — ver ficheiro 1 desta ronda).
-- RLS activo, SEM policies para authenticated/anon: só o service_role
-- (usado pela admin-api) consegue ler.
-- ──────────────────────────────────────────────────────────
create table if not exists public.super_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  note text
);
alter table public.super_admins enable row level security;

-- Regista o Kiko como super-admin (idempotente).
insert into public.super_admins (user_id, note)
select id, 'kiko - founder' from auth.users where email = 'kikocarujo@gmail.com'
on conflict (user_id) do nothing;

-- ──────────────────────────────────────────────────────────
-- 1. TENANT TAKEOVER (crítico) — o "link de convite" era só
-- `?tenant=<uuid>` em texto simples, e o formulário de signup deixava
-- o próprio utilizador escolher o role (incl. 'admin'). Qualquer
-- pessoa que visse o UUID de uma empresa (URL partilhada, captura de
-- ecrã, histórico do browser) conseguia registar-se como admin dessa
-- empresa sem convite nenhum — nem token, nem validação.
--
-- Fix: convites reais com token de utilização única + expiração,
-- numa tabela própria. tenant_id e role deixam de vir do cliente.
-- ──────────────────────────────────────────────────────────
create table if not exists public.tenant_invites (
  token       uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references public.tenants(id) on delete cascade,
  role        text not null default 'viewer' check (role in ('admin','supervisor','viewer')),
  assigned_countries text[] default '{}',
  created_by  uuid references public.profiles(id),
  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null default (now() + interval '14 days'),
  used_at     timestamptz,
  used_by     uuid references public.profiles(id)
);

alter table public.tenant_invites enable row level security;
-- Sem policies de propósito: só service_role e as funções
-- SECURITY DEFINER abaixo (create_invite/accept_invite) tocam nesta
-- tabela. Ninguém consegue fazer select/insert/update directo via API.

-- Cria um convite para o tenant do admin autenticado. Só quem já é
-- 'admin' do próprio tenant consegue gerar convites — nunca aceita
-- tenant_id vindo do cliente.
create or replace function public.create_invite(
  p_role text default 'viewer',
  p_assigned_countries text[] default '{}'
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

  insert into public.tenant_invites (tenant_id, role, assigned_countries, created_by)
  values (v_admin_tenant, p_role, coalesce(p_assigned_countries, '{}'), auth.uid())
  returning token into v_token;

  return jsonb_build_object('token', v_token, 'expires_at', now() + interval '14 days');
end;
$$;

-- Aceita um convite: associa o UTILIZADOR AUTENTICADO (auth.uid(),
-- nunca um id vindo do cliente) ao tenant/role/countries gravados no
-- convite. Recusa convites expirados, já usados, ou se o perfil já
-- tiver tenant atribuído (evita reassociar uma conta já activa).
create or replace function public.accept_invite(p_token uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_invite record;
  v_current_tenant uuid;
begin
  select tenant_id into v_current_tenant from public.profiles where id = auth.uid();
  if v_current_tenant is not null then
    raise exception 'This account is already associated with a company.';
  end if;

  select * into v_invite from public.tenant_invites where token = p_token for update;
  if v_invite is null then raise exception 'Invalid invite link.'; end if;
  if v_invite.used_at is not null then raise exception 'This invite link has already been used.'; end if;
  if v_invite.expires_at < now() then raise exception 'This invite link has expired.'; end if;

  update public.profiles
  set tenant_id = v_invite.tenant_id,
      role = v_invite.role,
      assigned_countries = v_invite.assigned_countries
  where id = auth.uid();

  update public.tenant_invites set used_at = now(), used_by = auth.uid() where token = p_token;

  return jsonb_build_object('tenant_id', v_invite.tenant_id, 'role', v_invite.role);
end;
$$;

revoke all on function public.create_invite(text, text[]) from public;
grant execute on function public.create_invite(text, text[]) to authenticated;
revoke all on function public.accept_invite(uuid) from public;
grant execute on function public.accept_invite(uuid) to authenticated;


-- ──────────────────────────────────────────────────────────
-- 2. handle_new_user() confiava cegamente em
-- raw_user_meta_data->>'tenant_id' e ->>'role', ambos controláveis
-- pelo próprio cliente na chamada a auth.signUp() — a app passava
-- literalmente o tenant_id do URL e o role escolhido no dropdown do
-- formulário. Um novo perfil nunca deve nascer já associado a um
-- tenant ou com um role escolhido pelo próprio: isso passa a ser
-- feito exclusivamente por accept_invite()/create_trial_tenant()/
-- create_pending_tenant(), que já validam correctamente.
-- Aproveita para fixar o search_path mutável (lint WARN).
-- ──────────────────────────────────────────────────────────
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role, tenant_id)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', new.email),
    'viewer',
    null
  );
  return new;
end;
$$;

-- ──────────────────────────────────────────────────────────
-- 3. check_tenant_limits() — mesmo lint (search_path mutável).
-- ──────────────────────────────────────────────────────────
create or replace function public.check_tenant_limits()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_tenant record;
  v_count  int;
begin
  select * into v_tenant from public.tenants where id = new.tenant_id;
  if v_tenant is null then return new; end if;

  if TG_TABLE_NAME = 'profiles' then
    select count(*) into v_count from public.profiles where tenant_id = new.tenant_id;
    if v_count >= v_tenant.max_users then
      raise exception 'Limite de utilizadores atingido para o plano %. Actualize o plano para adicionar mais.', v_tenant.plan;
    end if;
  end if;

  if TG_TABLE_NAME = 'inventory' then
    select count(distinct location) into v_count from public.inventory where tenant_id = new.tenant_id;
    if v_count >= v_tenant.max_locations
      and new.location not in (
        select distinct location from public.inventory where tenant_id = new.tenant_id
      )
    then
      raise exception 'Limite de localizações atingido para o plano %. Actualize o plano.', v_tenant.plan;
    end if;
  end if;

  return new;
end;
$$;

-- update_updated_at() não é SECURITY DEFINER (corre como o invoker),
-- por isso o risco de search_path hijack é bem menor, mas o lint
-- assinala-a na mesma — fixar por consistência.
create or replace function public.update_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;


-- ──────────────────────────────────────────────────────────
-- 4. create_trial_tenant() / create_pending_tenant() confiavam num
-- p_user_id vindo do cliente em vez de usar auth.uid() — um atacante
-- autenticado com QUALQUER conta podia passar o id de outra pessoa e
-- sequestrar o perfil dela (reassociar a um tenant novo, tornando-a
-- 'admin' de uma empresa diferente da que já usava). Passam a usar
-- sempre auth.uid() da sessão actual, nunca um parâmetro do cliente.
-- ──────────────────────────────────────────────────────────
drop function if exists public.create_trial_tenant(text,text,text,uuid,text,integer);
create or replace function public.create_trial_tenant(
  p_name text, p_slug text, p_email text, p_full_name text, p_trial_days integer default 14
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_tenant_id uuid;
  v_ends_at   timestamptz;
  v_caller    uuid := auth.uid();
begin
  if v_caller is null then raise exception 'Must be signed in.'; end if;
  if exists (select 1 from public.profiles where id = v_caller and tenant_id is not null) then
    raise exception 'This account is already associated with a company.';
  end if;

  v_ends_at := now() + (p_trial_days || ' days')::interval;

  insert into public.tenants (name, slug, plan, max_users, max_locations, billing_email, active, is_trial, trial_ends_at)
  values (p_name, p_slug, 'professional', 15, 10, p_email, true, true, v_ends_at)
  returning id into v_tenant_id;

  update public.profiles
  set tenant_id = v_tenant_id, role = 'admin', full_name = coalesce(p_full_name, full_name)
  where id = v_caller;

  return jsonb_build_object('tenant_id', v_tenant_id, 'trial_ends_at', v_ends_at, 'slug', p_slug);
end;
$$;

drop function if exists public.create_pending_tenant(text,text,text,uuid,text,text);
create or replace function public.create_pending_tenant(
  p_name text, p_slug text, p_email text, p_full_name text, p_plan text
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
  v_caller         uuid := auth.uid();
begin
  if v_caller is null then raise exception 'Must be signed in.'; end if;
  if exists (select 1 from public.profiles where id = v_caller and tenant_id is not null) then
    raise exception 'This account is already associated with a company.';
  end if;

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
  set tenant_id = v_tenant_id, role = 'admin', full_name = coalesce(p_full_name, full_name)
  where id = v_caller;

  return jsonb_build_object('tenant_id', v_tenant_id);
end;
$$;

revoke all on function public.create_trial_tenant(text,text,text,text,integer) from public;
grant execute on function public.create_trial_tenant(text,text,text,text,integer) to authenticated;
revoke all on function public.create_pending_tenant(text,text,text,text,text) from public;
grant execute on function public.create_pending_tenant(text,text,text,text,text) to authenticated;


-- ──────────────────────────────────────────────────────────
-- 5. activate_paid_subscription() estava, na prática, executável por
-- 'anon' e 'authenticated' (o REVOKE original em payments_paddle.sql
-- não sobreviveu a um CREATE OR REPLACE FUNCTION posterior — o
-- Postgres não preserva ACLs custom nesse caso, volta ao grant
-- por omissão a PUBLIC). Isto permitia a QUALQUER PESSOA, sem sessão
-- nenhuma, chamar /rest/v1/rpc/activate_paid_subscription e activar
-- qualquer tenant como pago de graça, ou forjar pagamentos. Único
-- caller legítimo é a Edge Function paddle-webhook, que usa
-- service_role — nunca precisa de estar acessível a anon/authenticated.
-- ──────────────────────────────────────────────────────────
revoke all on function public.activate_paid_subscription(uuid,text,numeric,text,text,text,text) from public, anon, authenticated;
grant execute on function public.activate_paid_subscription(uuid,text,numeric,text,text,text,text) to service_role;

-- update_user_role() já valida internamente que o caller é admin do
-- mesmo tenant do alvo — seguro por defeito mesmo exposta, mas
-- 'anon' nunca deveria conseguir sequer tentar (defesa em profundidade).
revoke all on function public.update_user_role(uuid,text,text[]) from public, anon;
grant execute on function public.update_user_role(uuid,text,text[]) to authenticated;


-- ──────────────────────────────────────────────────────────
-- 6. Verificação
-- ──────────────────────────────────────────────────────────
select routine_name, grantee, privilege_type
from information_schema.routine_privileges
where routine_schema = 'public'
  and routine_name in ('activate_paid_subscription','update_user_role','create_trial_tenant',
                        'create_pending_tenant','create_invite','accept_invite')
order by routine_name, grantee;
