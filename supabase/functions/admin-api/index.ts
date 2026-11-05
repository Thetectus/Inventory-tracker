// Secure backend for the /admin super-admin panel.
//
// Replaces the old admin/index.html pattern of shipping the
// service_role key straight to the browser. The service_role key now
// lives ONLY here, as an Edge Function secret, never in client code.
//
// Auth model: the caller must present a real Supabase Auth JWT
// (Authorization: Bearer <access_token>, obtained via
// supabase.auth.signInWithPassword using the ANON key in the browser).
// We verify that JWT server-side, then check the user's id against
// the `super_admins` table (RLS-locked, only service_role can read it)
// before performing any privileged action.
//
// Deploy: supabase functions deploy admin-api
// Secrets needed (already set for paddle-webhook, reused here):
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
// Also needs SUPABASE_ANON_KEY (used only to validate the caller's JWT).

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

const PLAN_LIMITS: Record<string, { max_users: number; max_locations: number }> = {
  starter: { max_users: 5, max_locations: 3 },
  professional: { max_users: 15, max_locations: 10 },
  enterprise: { max_users: 999, max_locations: 999 },
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const authHeader = req.headers.get("authorization") || "";
  const jwt = authHeader.replace(/^Bearer\s+/i, "");
  if (!jwt) return json({ error: "Missing bearer token" }, 401);

  // Client bound to the caller's own JWT: getUser() verifies the token's
  // signature/expiry against Supabase Auth itself (not decoded blindly).
  const callerClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${jwt}` } },
  });
  const { data: userData, error: userErr } = await callerClient.auth.getUser();
  if (userErr || !userData?.user) return json({ error: "Invalid session" }, 401);

  const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

  // Authorization: caller must be listed in super_admins.
  const { data: superAdmin } = await admin
    .from("super_admins")
    .select("user_id")
    .eq("user_id", userData.user.id)
    .maybeSingle();
  if (!superAdmin) return json({ error: "Forbidden — not a super admin" }, 403);

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }
  const action = body.action;

  if (action === "list_tenants") {
    const { data, error } = await admin
      .from("tenant_summary")
      .select("*")
      .order("created_at", { ascending: false });
    if (error) return json({ error: error.message }, 500);
    return json({ tenants: data });
  }

  if (action === "create_tenant") {
    const name = String(body.name || "").trim();
    const slug = String(body.slug || "").trim();
    const plan = String(body.plan || "");
    const billing_email = String(body.billing_email || "").trim();
    if (!name || !slug) return json({ error: "name and slug are required" }, 400);
    const limits = PLAN_LIMITS[plan];
    if (!limits) return json({ error: "Invalid plan" }, 400);

    const { data, error } = await admin
      .from("tenants")
      .insert({
        name,
        slug,
        plan,
        billing_email,
        max_users: limits.max_users,
        max_locations: limits.max_locations,
        active: true,
      })
      .select()
      .single();
    if (error) return json({ error: error.message }, 500);
    return json({ tenant: data });
  }

  if (action === "update_tenant") {
    const id = String(body.id || "");
    const plan = String(body.plan || "");
    const active = Boolean(body.active);
    if (!id) return json({ error: "id is required" }, 400);
    const limits = PLAN_LIMITS[plan];
    if (!limits) return json({ error: "Invalid plan" }, 400);

    const { error } = await admin
      .from("tenants")
      .update({ plan, active, max_users: limits.max_users, max_locations: limits.max_locations })
      .eq("id", id);
    if (error) return json({ error: error.message }, 500);
    return json({ ok: true });
  }

  if (action === "convert_to_paid") {
    // Manual conversion (bank transfer, or any payment taken off-Paddle)
    // for a trial/pending tenant. Paddle checkouts activate automatically
    // via the paddle-webhook; this is for the cases that don't go through
    // that flow.
    const id = String(body.id || "");
    const plan = String(body.plan || "");
    const amount = Number(body.amount);
    const currency = String(body.currency || "USD");
    const method = String(body.method || "bank_transfer");
    const reference = String(body.reference || "").trim();
    if (!id) return json({ error: "id is required" }, 400);
    const limits = PLAN_LIMITS[plan];
    if (!limits) return json({ error: "Invalid plan" }, 400);
    if (!Number.isFinite(amount) || amount < 0) return json({ error: "Invalid amount" }, 400);
    if (!["bank_transfer", "stripe", "flutterwave", "other"].includes(method)) {
      return json({ error: "Invalid method" }, 400);
    }

    const { error } = await admin.rpc("activate_paid_subscription", {
      p_tenant_id: id,
      p_plan: plan,
      p_amount: amount,
      p_currency: currency,
      p_reference: reference || `manual-${Date.now()}`,
      p_provider_tx_id: reference || `manual-${Date.now()}`,
      p_method: method,
    });
    if (error) return json({ error: error.message }, 500);
    return json({ ok: true });
  }

  if (action === "create_invite") {
    const tenant_id = String(body.tenant_id || "");
    const role = String(body.role || "viewer");
    const email = String(body.email || "").trim() || null;
    if (!tenant_id) return json({ error: "tenant_id is required" }, 400);
    if (!["admin", "supervisor", "viewer"].includes(role)) return json({ error: "Invalid role" }, 400);

    const { data, error } = await admin
      .from("tenant_invites")
      .insert({ tenant_id, role, created_by: null, email })
      .select("token, expires_at")
      .single();
    if (error) return json({ error: error.message }, 500);
    return json({ invite: data });
  }

  if (action === "list_payments") {
    const { data, error } = await admin
      .from("payments")
      .select("id, tenant_id, amount, currency, method, status, reference, notes, paid_at, tenants(name, slug)")
      .order("paid_at", { ascending: false })
      .limit(200);
    if (error) return json({ error: error.message }, 500);
    return json({ payments: data });
  }

  return json({ error: "Unknown action" }, 400);
});
