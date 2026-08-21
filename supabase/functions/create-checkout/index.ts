// Creates a Flutterwave hosted-checkout link for a pending FieldTrack
// subscription. Called from subscribe.html (anon key, no auth required —
// the tenant was already created in a 'pending' state by
// create_pending_tenant()). Holds FLW_SECRET_KEY server-side; never expose
// it to the client.
//
// Deploy: supabase functions deploy create-checkout
// Secrets: supabase secrets set FLW_SECRET_KEY=...

import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

const FLW_SECRET_KEY = Deno.env.get("FLW_SECRET_KEY")!;

const PLAN_PRICES: Record<string, number> = {
  starter: 299,
  professional: 799,
  enterprise: 1999,
};

serve(async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const { tenant_id, plan, email, company_name, redirect_url } = await req.json();
    const amount = PLAN_PRICES[plan];
    if (!tenant_id || !amount || !email || !redirect_url) {
      return json({ error: "Missing or invalid fields" }, 400);
    }

    const tx_ref = `fieldtrack-${tenant_id}-${Date.now()}`;

    const flwRes = await fetch("https://api.flutterwave.com/v3/payments", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${FLW_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        tx_ref,
        amount,
        currency: "USD",
        redirect_url,
        customer: { email, name: company_name },
        customizations: {
          title: `FieldTrack — ${plan}`,
          description: `Subscrição mensal FieldTrack (${plan})`,
        },
        // meta comes back verbatim in the webhook payload and in the
        // verify-transaction response — this is how the webhook knows
        // which tenant/plan to activate.
        meta: { tenant_id, plan },
      }),
    });

    const flwData = await flwRes.json();
    if (flwData.status !== "success") {
      return json({ error: flwData.message || "Flutterwave error creating payment link" }, 502);
    }

    return json({ checkout_url: flwData.data.link });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
