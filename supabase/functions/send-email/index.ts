// Centralized transactional email sender for FieldTrack. Called ONLY
// by Postgres triggers/cron via pg_net (never by the browser) — auth
// is a shared internal secret header, not a user JWT (there is no
// user session involved; this runs server-side off DB events).
//
// Deploy: supabase functions deploy send-email --no-verify-jwt
// Secrets: supabase secrets set RESEND_API_KEY=... FROM_EMAIL="FieldTrack <notifications@thetectus.com>" INTERNAL_SECRET=...
// (INTERNAL_SECRET must match the value stored in Supabase Vault as
// 'internal_secret' — see the dunning_emails migration.)

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY")!;
const FROM_EMAIL = Deno.env.get("FROM_EMAIL") || "FieldTrack <onboarding@resend.dev>";
const INTERNAL_SECRET = Deno.env.get("INTERNAL_SECRET")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const APP_URL = Deno.env.get("APP_URL") || "https://myinventorytracker.vercel.app";

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function sendResend(to: string, subject: string, html: string) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ from: FROM_EMAIL, to, subject, html }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Resend ${res.status}: ${body}`);
  }
}

function wrap(title: string, bodyHtml: string): string {
  return `<div style="font-family:-apple-system,Segoe UI,sans-serif;max-width:480px;margin:0 auto;padding:24px;color:#1a1a18">
    <h2 style="color:#0c447c;margin-bottom:16px">${title}</h2>
    ${bodyHtml}
    <p style="color:#9d9d98;font-size:12px;margin-top:32px">FieldTrack — The Tectus</p>
  </div>`;
}

const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

async function getTenantContactEmail(tenantId: string): Promise<string | null> {
  const { data, error } = await sb.rpc("get_tenant_contact_email", { p_tenant_id: tenantId });
  if (error || !data) return null;
  return data as string;
}

async function getTenant(tenantId: string) {
  const { data } = await sb.from("tenants").select("name, slug, plan").eq("id", tenantId).single();
  return data;
}

serve(async (req) => {
  const secretHeader = req.headers.get("x-internal-secret") || "";
  if (!secretHeader || !timingSafeEqual(secretHeader, INTERNAL_SECRET)) {
    return new Response("Forbidden", { status: 403 });
  }
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

  let body: { event: string; payload: Record<string, unknown> };
  try {
    body = await req.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }
  const { event, payload } = body;

  try {
    if (event === "welcome_trial") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        `Bem-vindo ao FieldTrack, ${tenant.name}!`,
        wrap("A tua conta está pronta", `
          <p>Olá,</p>
          <p>A conta de <strong>${tenant.name}</strong> foi criada com sucesso no FieldTrack, em período de avaliação gratuita de 14 dias.</p>
          <p><a href="${APP_URL}" style="background:#0c447c;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block">Abrir o FieldTrack</a></p>
          <p>Qualquer dúvida, responde a este email.</p>
        `),
      );
    } else if (event === "welcome_pending") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        `FieldTrack — confirmação de registo`,
        wrap("Falta só confirmar o pagamento", `
          <p>Olá,</p>
          <p>A conta de <strong>${tenant.name}</strong> (plano ${tenant.plan}) foi criada e fica activa automaticamente assim que o pagamento for confirmado.</p>
        `),
      );
    } else if (event === "payment_confirmed") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        `Pagamento confirmado — ${tenant.name}`,
        wrap("A tua subscrição está activa", `
          <p>Recebemos o pagamento e a conta de <strong>${tenant.name}</strong> (plano ${tenant.plan}) está activa.</p>
          <p><a href="${APP_URL}" style="background:#0c447c;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block">Abrir o FieldTrack</a></p>
        `),
      );
    } else if (event === "payment_failed") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        `Falha no pagamento — ${tenant.name}`,
        wrap("Não foi possível processar o pagamento", `
          <p>Tentámos cobrar a subscrição de <strong>${tenant.name}</strong> e não foi possível. Vamos tentar novamente automaticamente nos próximos dias.</p>
          <p>Verifica se o cartão associado está válido para evitar a suspensão do acesso.</p>
        `),
      );
    } else if (event === "past_due") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        `Acção necessária — pagamento em atraso (${tenant.name})`,
        wrap("A tua subscrição está em atraso", `
          <p>Já tentámos cobrar algumas vezes sem sucesso. O acesso de <strong>${tenant.name}</strong> continua activo por agora, mas será suspenso se o pagamento não for regularizado em breve.</p>
        `),
      );
    } else if (event === "cancelled") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        `Subscrição cancelada — ${tenant.name}`,
        wrap("A tua subscrição foi cancelada", `
          <p>A subscrição de <strong>${tenant.name}</strong> foi cancelada e o acesso ao FieldTrack foi suspenso.</p>
          <p>Se foi um erro, responde a este email e ajudamos a reactivar.</p>
        `),
      );
    } else if (event === "trial_reminder") {
      const tenantId = String(payload.tenant_id);
      const daysLeft = Number(payload.days_left);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        daysLeft <= 1
          ? `O teu trial termina hoje/amanhã — ${tenant.name}`
          : `Faltam ${daysLeft} dias de trial — ${tenant.name}`,
        wrap("O teu período de avaliação está a terminar", `
          <p>Faltam <strong>${daysLeft} dia(s)</strong> para o fim do trial gratuito de <strong>${tenant.name}</strong>.</p>
          <p>Subscreve agora para não perderes o acesso ao inventário.</p>
          <p><a href="${APP_URL}" style="background:#0c447c;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block">Subscrever</a></p>
        `),
      );
    } else if (event === "trial_expired") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      await sendResend(
        to,
        `O teu trial terminou — ${tenant.name}`,
        wrap("O período de avaliação terminou", `
          <p>O trial gratuito de <strong>${tenant.name}</strong> terminou e o acesso foi bloqueado.</p>
          <p>Subscreve para reactivar — os teus dados continuam guardados.</p>
        `),
      );
    } else if (event === "invite") {
      const to = String(payload.email || "");
      const tenantId = String(payload.tenant_id);
      const token = String(payload.token);
      const role = String(payload.role || "viewer");
      const tenant = await getTenant(tenantId);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const inviteUrl = `${APP_URL}?invite=${token}`;
      await sendResend(
        to,
        `Convite para te juntares a ${tenant.name} no FieldTrack`,
        wrap(`Foste convidado para ${tenant.name}`, `
          <p>Foste convidado como <strong>${role}</strong> para a equipa de <strong>${tenant.name}</strong> no FieldTrack.</p>
          <p><a href="${inviteUrl}" style="background:#0c447c;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;display:inline-block">Aceitar convite</a></p>
          <p style="color:#9d9d98;font-size:12px">Este link é de uso único e expira em 14 dias.</p>
        `),
      );
    } else {
      return new Response("Unknown event", { status: 400 });
    }
  } catch (e) {
    console.error(e);
    return new Response("Send failed: " + (e as Error).message, { status: 500 });
  }

  return new Response("OK", { status: 200 });
});
