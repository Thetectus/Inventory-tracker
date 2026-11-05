// Centralized transactional email sender for FieldTrack. Called ONLY
// by Postgres triggers/cron via pg_net (never by the browser) — auth
// is a shared internal secret header, not a user JWT (there is no
// user session involved; this runs server-side off DB events).
//
// Deploy: supabase functions deploy send-email --no-verify-jwt
// Secrets: supabase secrets set RESEND_API_KEY=... FROM_EMAIL="FieldTrack <notifications@thetectus.com>" INTERNAL_SECRET=...
// (INTERNAL_SECRET must match the value stored in Supabase Vault as
// 'internal_secret' — see the automated_emails migration.)

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

// Tenant names, emails, invite roles etc. are all user-controlled —
// anyone can self-serve-signup with an arbitrary company name (no
// validation on that field) and it flows straight into these HTML
// emails. Without escaping, a crafted name could inject markup/links
// into an email sent from our trusted domain (phishing risk), even
// though most mail clients won't execute <script>. Escape everything
// that isn't a literal we wrote ourselves, for the HTML body.
function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Subjects are plain text, not HTML — entity-escaping would show
// literal "&amp;" to the recipient. Just strip newlines/control
// characters (defends against any header-injection-style trick) and
// angle brackets (so a crafted name can't look like a tag even in a
// plain-text context).
function sanitizeSubject(s: string): string {
  return s.replace(/[\r\n\x00-\x1f<>]/g, "").slice(0, 200);
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

const PLAN_LABEL: Record<string, string> = {
  starter: "Starter",
  professional: "Professional",
  enterprise: "Enterprise",
};

function fmtDate(iso?: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("pt-PT", { day: "2-digit", month: "long", year: "numeric" });
}

function fmtMoney(amount?: number | string | null, currency?: string | null): string {
  if (amount === undefined || amount === null) return "—";
  const n = Number(amount);
  return `${n.toLocaleString("pt-PT", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} ${escapeHtml(currency || "USD")}`;
}

const METHOD_LABEL: Record<string, string> = {
  paddle: "Cartão (Paddle)",
  bank_transfer: "Transferência bancária",
  stripe: "Stripe",
  flutterwave: "Flutterwave",
  other: "Outro",
};

// Shared visual shell — warmer tone: a coloured header band, a proper
// signature, and room for an optional "receipt" details table.
// Callers must pass already-escaped HTML in heading/intro/bodyHtml —
// this function does not escape (it also accepts literal markup we
// wrote ourselves, e.g. <strong> tags around already-escaped names).
function wrap(opts: { preheader?: string; heading: string; intro: string; bodyHtml: string; ctaLabel?: string; ctaUrl?: string }): string {
  const cta = opts.ctaUrl
    ? `<p style="margin:28px 0 8px"><a href="${opts.ctaUrl}" style="background:#0c447c;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;font-weight:600;font-size:14px">${opts.ctaLabel || "Abrir o FieldTrack"}</a></p>`
    : "";
  return `<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:520px;margin:0 auto;background:#ffffff">
    ${opts.preheader ? `<span style="display:none;max-height:0;overflow:hidden">${opts.preheader}</span>` : ""}
    <div style="background:linear-gradient(135deg,#0c447c,#1a6cb8);padding:28px 32px;border-radius:12px 12px 0 0">
      <div style="color:#fff;font-size:20px;font-weight:700;letter-spacing:-0.02em">FieldTrack</div>
    </div>
    <div style="padding:32px;border:1px solid #e5e5e3;border-top:none;border-radius:0 0 12px 12px">
      <h2 style="color:#0c2f4f;margin:0 0 12px;font-size:20px">${opts.heading}</h2>
      <p style="color:#44443f;font-size:15px;line-height:1.6;margin:0 0 20px">${opts.intro}</p>
      ${opts.bodyHtml}
      ${cta}
      <p style="color:#6b6b67;font-size:14px;line-height:1.6;margin-top:28px">Qualquer dúvida, é só responder a este email — lemos tudo pessoalmente.</p>
      <p style="color:#1a1a18;font-size:14px;margin-top:20px">Obrigado por confiares em nós,<br><strong>Equipa The Tectus</strong></p>
    </div>
    <p style="color:#9d9d98;font-size:11px;text-align:center;margin-top:16px">FieldTrack é um produto da The Tectus &middot; thetectus.com</p>
  </div>`;
}

// Labels are our own literals (safe); values may be user-controlled
// and must already be escaped by the caller before reaching here.
function receiptTable(rows: [string, string][]): string {
  return `<table style="width:100%;border-collapse:collapse;background:#f7f7f5;border-radius:10px;overflow:hidden;margin:4px 0 20px">
    ${rows.map(([label, value], i) => `
      <tr>
        <td style="padding:12px 16px;color:#6b6b67;font-size:13px;border-bottom:${i < rows.length - 1 ? "1px solid #e5e5e3" : "none"}">${label}</td>
        <td style="padding:12px 16px;color:#1a1a18;font-size:13px;font-weight:600;text-align:right;border-bottom:${i < rows.length - 1 ? "1px solid #e5e5e3" : "none"}">${value}</td>
      </tr>`).join("")}
  </table>`;
}

const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

async function getTenantContactEmail(tenantId: string): Promise<string | null> {
  const { data, error } = await sb.rpc("get_tenant_contact_email", { p_tenant_id: tenantId });
  if (error || !data) return null;
  return data as string;
}

async function getTenant(tenantId: string) {
  const { data } = await sb.from("tenants").select("name, slug, plan, billing_email").eq("id", tenantId).single();
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
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      const trialEndsAt = payload.trial_ends_at ? String(payload.trial_ends_at) : null;
      await sendResend(
        to,
        `Bem-vindo ao FieldTrack, ${subjName}! 🎉`,
        wrap({
          heading: `Bem-vindo, ${name}!`,
          intro: `A tua conta está pronta a usar. Preparámos 14 dias de avaliação gratuita, sem precisares de cartão de crédito, para conheceres o FieldTrack com calma.`,
          bodyHtml: receiptTable([
            ["Empresa", name],
            ["Email de contacto", escapeHtml(to)],
            ["Plano em avaliação", escapeHtml(PLAN_LABEL[tenant.plan] || tenant.plan)],
            ["Trial termina em", fmtDate(trialEndsAt)],
          ]),
          ctaLabel: "Abrir o FieldTrack",
          ctaUrl: APP_URL,
        }),
      );
    } else if (event === "welcome_pending") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      await sendResend(
        to,
        `FieldTrack — falta só confirmar o pagamento`,
        wrap({
          heading: "Quase lá!",
          intro: `Recebemos o registo de <strong>${name}</strong>. A conta fica activa automaticamente assim que confirmarmos o pagamento — normalmente é instantâneo.`,
          bodyHtml: receiptTable([
            ["Empresa", name],
            ["Email de contacto", escapeHtml(to)],
            ["Plano escolhido", escapeHtml(PLAN_LABEL[tenant.plan] || tenant.plan)],
          ]),
        }),
      );
    } else if (event === "payment_confirmed") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      const amount = payload.amount as number | string | undefined;
      const currency = payload.currency as string | undefined;
      const method = payload.method as string | undefined;
      const reference = payload.reference as string | undefined;
      const paidAt = payload.paid_at as string | undefined;
      const invoiceUrl = payload.invoice_url as string | undefined;
      const invoiceLink = invoiceUrl
        ? `<p style="margin:0 0 20px"><a href="${escapeHtml(invoiceUrl)}" style="color:#0c447c;font-size:14px;font-weight:600;text-decoration:none">📄 Ver recibo oficial (PDF)</a></p>`
        : method === "paddle"
          ? `<p style="color:#9d9d98;font-size:12px;margin:0 0 20px">O recibo fiscal oficial é enviado separadamente pela Paddle, nosso processador de pagamentos.</p>`
          : "";
      await sendResend(
        to,
        `Recibo — pagamento confirmado (${subjName})`,
        wrap({
          heading: "Pagamento recebido, obrigado!",
          intro: `A subscrição de <strong>${name}</strong> está activa. Aqui tens o resumo para os teus registos${invoiceUrl ? " — e o recibo oficial da Paddle logo abaixo" : ""}:`,
          bodyHtml: receiptTable([
            ["Empresa", name],
            ["Plano", escapeHtml(PLAN_LABEL[tenant.plan] || tenant.plan)],
            ["Valor pago", fmtMoney(amount, currency)],
            ["Método", escapeHtml(METHOD_LABEL[method || ""] || method || "—")],
            ["Referência", escapeHtml(reference || "—")],
            ["Data", fmtDate(paidAt)],
          ]) + invoiceLink,
          ctaLabel: "Abrir o FieldTrack",
          ctaUrl: APP_URL,
        }),
      );
    } else if (event === "payment_failed") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      const amount = payload.amount as number | string | undefined;
      const currency = payload.currency as string | undefined;
      await sendResend(
        to,
        `Não conseguimos processar o pagamento — ${subjName}`,
        wrap({
          heading: "Houve um problema com o pagamento",
          intro: `Tentámos cobrar a subscrição de <strong>${name}</strong> e não foi possível desta vez. Vamos tentar novamente automaticamente nos próximos dias — não precisas de fazer nada já, mas vale a pena confirmar que o cartão está válido.`,
          bodyHtml: amount ? receiptTable([
            ["Empresa", name],
            ["Valor da tentativa", fmtMoney(amount, currency)],
          ]) : "",
        }),
      );
    } else if (event === "past_due") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      await sendResend(
        to,
        `Acção necessária — pagamento em atraso (${subjName})`,
        wrap({
          heading: "Precisamos de actualizar o teu pagamento",
          intro: `Já tentámos cobrar a subscrição de <strong>${name}</strong> algumas vezes sem sucesso. O acesso continua activo por agora, mas pode ser suspenso se não regularizares o pagamento em breve.`,
          bodyHtml: "",
        }),
      );
    } else if (event === "cancelled") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      await sendResend(
        to,
        `Subscrição cancelada — ${subjName}`,
        wrap({
          heading: "A tua subscrição foi cancelada",
          intro: `A subscrição de <strong>${name}</strong> foi cancelada e o acesso ao FieldTrack foi suspenso. Os teus dados continuam guardados em segurança.`,
          bodyHtml: "<p style=\"color:#44443f;font-size:14px\">Se isto foi um engano, responde a este email e ajudamos a reactivar a conta.</p>",
        }),
      );
    } else if (event === "trial_reminder") {
      const tenantId = String(payload.tenant_id);
      const daysLeft = Number(payload.days_left);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      await sendResend(
        to,
        daysLeft <= 1
          ? `O teu trial termina hoje/amanhã — ${subjName}`
          : `Faltam ${daysLeft} dias de trial — ${subjName}`,
        wrap({
          heading: "O teu período de avaliação está a terminar",
          intro: `Faltam <strong>${daysLeft} dia(s)</strong> para o fim do trial gratuito de <strong>${name}</strong>. Subscreve agora para não perderes o acesso ao teu inventário.`,
          bodyHtml: "",
          ctaLabel: "Subscrever agora",
          ctaUrl: APP_URL,
        }),
      );
    } else if (event === "trial_expired") {
      const tenantId = String(payload.tenant_id);
      const [to, tenant] = await Promise.all([getTenantContactEmail(tenantId), getTenant(tenantId)]);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      await sendResend(
        to,
        `O teu trial terminou — ${subjName}`,
        wrap({
          heading: "O período de avaliação terminou",
          intro: `O trial gratuito de <strong>${name}</strong> terminou e o acesso foi bloqueado. Os teus dados continuam guardados — subscreve para reactivar.`,
          bodyHtml: "",
          ctaLabel: "Subscrever",
          ctaUrl: APP_URL,
        }),
      );
    } else if (event === "invite") {
      const to = String(payload.email || "");
      const tenantId = String(payload.tenant_id);
      const token = String(payload.token);
      const roleRaw = String(payload.role || "viewer");
      const role = escapeHtml(roleRaw);
      const tenant = await getTenant(tenantId);
      if (!to || !tenant) return new Response("No recipient", { status: 200 });
      const name = escapeHtml(tenant.name);
      const subjName = sanitizeSubject(tenant.name);
      const inviteUrl = `${APP_URL}?invite=${encodeURIComponent(token)}`;
      await sendResend(
        to,
        `Foste convidado para ${subjName} no FieldTrack`,
        wrap({
          heading: `Junta-te a ${name}`,
          intro: `Foste convidado como <strong>${role}</strong> para a equipa de <strong>${name}</strong> no FieldTrack.`,
          bodyHtml: "<p style=\"color:#9d9d98;font-size:12px\">Este link é de uso único e expira em 14 dias.</p>",
          ctaLabel: "Aceitar convite",
          ctaUrl: inviteUrl,
        }),
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
