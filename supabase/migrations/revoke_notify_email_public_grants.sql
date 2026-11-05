-- ============================================================
-- FIELDTRACK — Revoke public access to notify_email (2026-11-05)
-- Parte da verificação de segurança pedida pelo Kiko ("verifica
-- todos"). notify_email é SECURITY DEFINER e estava executável por
-- anon/authenticated via RPC — qualquer utilizador autenticado (ou
-- anon) podia forjar eventos arbitrários (ex: payment_confirmed falso
-- com invoice_url de phishing) enviados do domínio de confiança
-- thetectus.com para o email real de qualquer tenant. As funções de
-- trigger que chamam notify_email são elas próprias SECURITY DEFINER
-- (owned by postgres), por isso não precisam desta grant — só
-- service_role/postgres devem poder invocar directamente.
-- ============================================================

revoke all on function public.notify_email(text, jsonb) from public, anon, authenticated;
grant execute on function public.notify_email(text, jsonb) to service_role, postgres;
