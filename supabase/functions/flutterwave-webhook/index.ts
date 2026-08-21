// Receives Flutterwave webhook events. Verifies the signature header,
// re-verifies the transaction directly against Flutterwave's API (never
// trust the webhook body alone — it can be spoofed), then activates the
// tenant via the activate_paid_subscription() SQL function using the
// service role key.
//
// Deploy: supabase functions deploy flutterwave-webhook --no-verify-jwt
// (--no-verify-jwt because Flutterwave calls this anonymously — auth is
// via the verif-hash header instead, checked below)
// Secrets: supabase secrets set FLW_SECRET_KEY=... FLW_SECRET_HASH=...
// Configure this function's URL as the webhook URL in the Flutterwave
// dashboard, and set the same value there as FLW_SECRET_HASH.

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const FLW_SECRET_HASH = Deno.env.get("FLW_SECRET_HASH")!;
const FLW_SECRET_KEY = Deno.env.get("FLW_SECRET_KEY")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

serve(async (req) => {
  const signature = req.headers.get("verif-hash");
  if (!signature || signature !== FLW_SECRET_HASH) {
    return new Response("Unauthorized", { status: 401 });
  }

  const payload = await req.json();
  if (payload.event !== "charge.completed" || payload.data?.status !== "successful") {
    return new Response("Ignored (not a successful charge)", { status: 200 });
  }

  // Re-verify with Flutterwave directly instead of trusting the payload.
  const verifyRes = await fetch(
    `https://api.flutterwave.com/v3/transactions/${payload.data.id}/verify`,
    { headers: { Authorization: `Bearer ${FLW_SECRET_KEY}` } },
  );
  const verify = await verifyRes.json();
  if (verify.status !== "success" || verify.data?.status !== "successful") {
    return new Response("Verification failed", { status: 400 });
  }

  const { tenant_id, plan } = verify.data.meta || {};
  if (!tenant_id || !plan) {
    return new Response("Missing tenant_id/plan in transaction meta", { status: 400 });
  }

  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  const { error } = await sb.rpc("activate_paid_subscription", {
    p_tenant_id: tenant_id,
    p_plan: plan,
    p_amount: verify.data.amount,
    p_currency: verify.data.currency,
    p_reference: verify.data.tx_ref,
    p_flw_tx_id: String(verify.data.id),
  });
  if (error) {
    return new Response("DB error: " + error.message, { status: 500 });
  }

  return new Response("OK", { status: 200 });
});
