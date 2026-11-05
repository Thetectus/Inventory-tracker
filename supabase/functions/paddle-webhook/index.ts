// Receives Paddle webhook notifications. Verifies the Paddle-Signature
// header (HMAC-SHA256 over "timestamp:raw_body" using the notification
// destination's secret key — never trust the payload without this),
// then activates the tenant via activate_paid_subscription() using the
// service role key.
//
// Deploy: supabase functions deploy paddle-webhook --no-verify-jwt
// (--no-verify-jwt because Paddle calls this anonymously — auth is via
// the Paddle-Signature header instead, checked below)
// Secrets: supabase secrets set PADDLE_WEBHOOK_SECRET=... PADDLE_API_KEY=...
// Configure this function's URL as a Notification destination in the
// Paddle dashboard (Developer Tools -> Notifications), subscribed at
// least to transaction.completed. The secret shown there when you
// create the destination is PADDLE_WEBHOOK_SECRET.
//
// PADDLE_API_KEY is a different secret (Developer Tools -> Authentication
// -> API keys, NOT the client-side token) used server-side only, to fetch
// the official invoice PDF URL for each confirmed transaction so our
// receipt email can link to it. Optional: if unset, payments just get no
// invoice_url and the email omits the "official receipt" link.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const PADDLE_WEBHOOK_SECRET = Deno.env.get("PADDLE_WEBHOOK_SECRET")!;
const PADDLE_API_KEY = Deno.env.get("PADDLE_API_KEY");
const PADDLE_API_BASE = Deno.env.get("PADDLE_API_BASE") || "https://sandbox-api.paddle.com";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Fetches the hosted PDF URL for a transaction's invoice from Paddle's
// API. Best-effort: Paddle generates the invoice asynchronously, so this
// can occasionally 404 right after transaction.completed — that's fine,
// the payment is still recorded, just without a receipt link.
async function fetchInvoiceUrl(transactionId: string): Promise<string | null> {
  if (!PADDLE_API_KEY) return null;
  try {
    const res = await fetch(`${PADDLE_API_BASE}/transactions/${transactionId}/invoice`, {
      headers: { Authorization: `Bearer ${PADDLE_API_KEY}` },
    });
    if (!res.ok) return null;
    const body = await res.json();
    return body?.data?.url ?? null;
  } catch {
    return null;
  }
}

serve(async (req) => {
  const signatureHeader = req.headers.get("paddle-signature");
  const rawBody = await req.text();

  if (!signatureHeader || !(await isValidSignature(signatureHeader, rawBody))) {
    return new Response("Invalid signature", { status: 401 });
  }

  const event = JSON.parse(rawBody);
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  if (event.event_type === "transaction.completed") {
    const tx = event.data;
    const tenant_id = tx.custom_data?.tenant_id;
    const plan = tx.custom_data?.plan;
    if (!tenant_id || !plan) {
      return new Response("Missing tenant_id/plan in custom_data", { status: 400 });
    }

    const totals = tx.details?.totals;
    const amountMinor = totals?.total ?? "0"; // Paddle amounts are strings in the lowest denomination
    const currency = totals?.currency_code ?? "USD";
    const amount = Number(amountMinor) / 100;

    // Fetched BEFORE activating, so the invoice link lands in the same
    // payments row the welcome-email trigger reads (an AFTER INSERT
    // trigger, so an UPDATE afterwards would be too late to be included).
    // Best-effort: null is fine, the receipt email just omits the link.
    const invoiceUrl = await fetchInvoiceUrl(tx.id);

    const { error } = await sb.rpc("activate_paid_subscription", {
      p_tenant_id: tenant_id,
      p_plan: plan,
      p_amount: amount,
      p_currency: currency,
      p_reference: tx.id,
      p_provider_tx_id: tx.id,
      p_method: "paddle",
      p_invoice_url: invoiceUrl,
    });
    if (error) return new Response("DB error: " + error.message, { status: 500 });
    return new Response("OK", { status: 200 });
  }

  if (event.event_type === "transaction.payment_failed") {
    const tx = event.data;
    const tenant_id = tx.custom_data?.tenant_id;
    if (!tenant_id) return new Response("Missing tenant_id in custom_data", { status: 400 });

    const totals = tx.details?.totals;
    const amount = Number(totals?.total ?? "0") / 100;
    const currency = totals?.currency_code ?? "USD";

    const { error } = await sb.rpc("record_failed_payment", {
      p_tenant_id: tenant_id,
      p_amount: amount,
      p_currency: currency,
      p_reference: tx.id,
      p_provider_tx_id: tx.id,
      p_method: "paddle",
    });
    if (error) return new Response("DB error: " + error.message, { status: 500 });
    return new Response("OK", { status: 200 });
  }

  // subscription.past_due / subscription.canceled: Paddle puts
  // custom_data on the subscription object (copied from the checkout
  // that created it), not on a transaction.
  if (event.event_type === "subscription.past_due" || event.event_type === "subscription.canceled") {
    const sub = event.data;
    const tenant_id = sub.custom_data?.tenant_id;
    if (!tenant_id) return new Response("Missing tenant_id in custom_data", { status: 400 });

    const status = event.event_type === "subscription.past_due" ? "past_due" : "cancelled";
    const { error } = await sb.rpc("set_subscription_status", {
      p_tenant_id: tenant_id,
      p_status: status,
    });
    if (error) return new Response("DB error: " + error.message, { status: 500 });
    return new Response("OK", { status: 200 });
  }

  return new Response("Ignored (unhandled event_type)", { status: 200 });
});

// Paddle-Signature header format: "ts=<unix_ts>;h1=<hex_hmac>"
// HMAC-SHA256 is computed over `${ts}:${rawBody}` using the
// notification destination's secret key.
async function isValidSignature(header: string, rawBody: string): Promise<boolean> {
  const parts = Object.fromEntries(
    header.split(";").map((p) => p.split("=") as [string, string]),
  );
  const ts = parts["ts"];
  const h1 = parts["h1"];
  if (!ts || !h1) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(PADDLE_WEBHOOK_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${ts}:${rawBody}`),
  );
  const computedHex = Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return timingSafeEqual(computedHex, h1);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}
