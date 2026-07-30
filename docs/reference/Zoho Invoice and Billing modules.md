---
aliases: [Zoho modules, Zoho reference]
tags: [reference, billing, domain]
updated: 2026-07-30
---

> [!note] Domain reference, not a specification
> The product this project is modelled on. Useful for vocabulary and module
> boundaries — see [[Glossary#Billing domain]]. Nothing here is a commitment.

# Zoho Invoice & Zoho Billing — Complete Module-by-Module Guide

A simple, end-to-end explanation of every module in both apps, how each works, and how they connect together.

---

# PART 1: ZOHO INVOICE

**What it is:** A free tool for creating invoices, sending them to customers, and collecting payments. Best for freelancers, service providers, and small businesses that bill per job or per hour.

**Important limitation:** Zoho Invoice has no purchase-side modules (no Vendors, Purchase Orders, or Bills). It only records *your expenses*. For full purchase management, Zoho Books is needed.

## 1. Dashboard
- The home screen you land on.
- Shows an overview of your company's sales and expenses, top projects, due receivables (money owed to you), and more.
- Think of it as a health check: how much money is owed to you, how much you've spent, and which projects earn the most.

## 2. Customers (Contacts)
- Your customer address book. Every invoice, quote, or payment links to a customer here.
- Stores per customer: name, email, billing/shipping address, currency, payment terms (e.g., "pay within 15 days"), and tax details.
- Full history per customer: all invoices, payments, unpaid amounts, and emails sent.
- **Customer Portal:** invite the customer to a private webpage where they view invoices and pay directly.

## 3. Items
- Your saved list of products/services so you never retype them.
- Each item = name + description + rate (price) + tax.
- When creating an invoice, pick the item and details fill in automatically.

## 4. Quotes (Estimates)
- A price proposal sent *before* the sale — prices, discounts, terms and conditions.
- **Flow:**
  1. Create quote → email it or share via portal.
  2. Customer accepts, declines, or comments.
  3. Add expiration dates to push quick decisions; get quotes digitally signed via Zoho Sign.
  4. Once accepted → one click converts the quote into an invoice (or a project). No retyping.

## 5. Invoices (core module)
- A document recording the sale of goods/services — the customer owes you money, with a payment due date.
- **Invoice life cycle:**
  - **Draft** — you're preparing it; customer hasn't seen it.
  - **Sent** — emailed / shared via portal link.
  - **Viewed** — customer opened it.
  - **Partially Paid / Paid** — money received (part or full).
  - **Overdue** — due date passed; automatic reminders can fire.
  - **Void / Written off** — cancelled or given up on.
- **Also possible:** create fresh or convert a quote; attach documents/photos; record cash payments manually; edit; download PDF / print / delete.
- **Recurring invoices:** set a schedule (e.g., monthly) and invoices are created/sent automatically.
- **Payment collection:** 10+ payment gateway integrations (PayPal, Stripe, etc.); save customer cards and charge automatically; automatic payment reminders.

## 6. Payments Received
- Every incoming payment — online (gateway) or offline (cash, cheque, bank transfer recorded manually).
- Each payment matches its invoice, so status updates to Paid automatically.
- Also handles retainer/advance payments (applied to future invoices) and refunds.

## 7. Credit Notes
- Used when *you* owe the customer money — returns or overcharges.
- Refund in cash, or keep as credit applied to their next invoice.

## 8. Expenses
- Track business spending.
- **Billable expenses:** link an expense to a customer → convert to an invoice line in one click.
  - Example: buy $50 of materials for a client's job → record as billable → appears on their next invoice.
- Categorize expenses for clean reporting; track mileage and convert billable miles to money.
- Recurring expenses (rent, software) can be automated.

## 9. Time Tracking (Projects & Timesheets)
- For hourly billing.
- **Flow:** create Project for a client → add tasks → log hours (manual or timer) → convert tracked time into invoices.
- Billing methods per project: fixed cost, hourly per project, hourly per task, or hourly per staff member.

## 10. Reports
- Sales by customer/item, payments received, expenses, project time, taxes collected, receivables aging (who owes you and for how long).
- Use for tax filing and to see which customers/services are most profitable.

## 11. Settings (Gear icon)
- Organization details, taxes, invoice templates (logo, colors), email templates, reminders, users & roles, payment gateways, custom fields, and automation.

**Zoho Invoice end-to-end in one line:**
Add customer → add items → send quote → quote accepted → convert to invoice → customer pays via portal/gateway → payment recorded → reports show your income.

---

# PART 2: ZOHO BILLING

**What it is:** Everything Zoho Invoice does, **plus subscription/recurring billing**. Built for businesses that charge customers repeatedly — SaaS, gyms, ISPs, memberships, usage-based services.

**Module visibility note:** The sidebar has **8 main sections** containing roughly **16–17 working modules**. What you actually see depends on what's enabled under **Settings > Preferences > General** — check a module there and it appears in your left sidebar. If something from this guide is missing in your app, it's switched off, not absent.

## MODULE 1: Home (Dashboard)
- Business summary screen: sales, receivables, expenses, project performance.
- **Total Receipts** → click to open the Payment Received report.
- **Total Expenses** → click to open the Expense Details report.
- **Projects section** → links straight into each project in the Timesheet module.
- **Top expenses pie chart** → auto-generated from the Expense by Category report.
- Subscription metrics on top: **MRR** (predictable monthly revenue), **churn** (cancellations), activations, net revenue.
- **Use pattern:** open app → glance → click any number → drill into the full report behind it.

## MODULE 2: Customers
- Master record of everyone you bill: name, email, addresses, currency, payment terms, tax treatment, saved cards/payment methods.
- Open a customer → see their whole life with you: subscriptions, invoices, payments, credits, unpaid balance, emails.
- **Create transactions from here:** select customer → New Transaction → Subscription → pick Product, Plan, Addons, Coupons → Continue → Create.
- Invite customers to the Customer Portal from this module.
- **End-to-end:** add customer → set currency/terms/tax → invite to portal → create subscription or invoice → track balance and history forever from one page.

## MODULE 3: Product Catalog (4 sub-modules)
The foundation of everything recurring. Build your "menu" once; all subscriptions are assembled from it.

> **Jan 2026 update:** Plans, Addons, and Coupons (previously grouped as "Subscription Items") now each have **dedicated modules** with list/detail views, filters, sorting, column customization, advanced search, and bulk-update actions.

### 3a. Products
- A product = a service you offer. Multiple services (e.g., a bug tracker AND a project management tool) = separate products, each with its own plans, addons, and coupons — and separate performance reports.
- Inside a product: details + associated plans/addons/coupons in separate tabs; create new ones directly there and they auto-link to that product.

### 3b. Plans
- Pricing tiers of a product: name, code, price, billing frequency (weekly/monthly/yearly/custom), number of cycles (fixed or forever), free-trial length.
- Example: Basic $10/mo, Pro $25/mo, Pro Yearly $250/yr.
- **Price lists:** custom rates for specific customers or items (up or down) without creating new plans.

### 3c. Addons
- Optional extras on top of a plan (e.g., extra storage, priority support) — no need to create whole new plans.
- **Two types:**
  - **One-time** — paid once at subscription.
  - **Recurring** — paid every billing cycle along with the plan.
- One addon can link to multiple plans of a product.
- **Mandatory** addons = auto-included for everyone on that plan. **Recommended** addons = shown as optional on the hosted payment page.
- **Restrict Overage:** for usage addons, stops customers from consuming beyond their allocated units.

### 3d. Coupons
- Discount codes: one-time, unlimited, or time-defined; percentage or flat; tied to specific products or addons; with validity dates and redemption limits.

**Catalog end-to-end:** create Product → add Plans → attach Addons → create Coupons → every future subscription is just "pick from the catalog."

## MODULE 4: Items
- Simple one-time goods/services (NOT subscriptions): name, description, rate, tax.
- Used on normal one-off invoices/quotes — setup fees, consulting sessions, hardware.
- Configured under Settings > Preferences > Items.

## MODULE 5: Sales (5 sub-modules)
Where all money-transactions live.

### 5a. Quotes
- Price proposals; customers view, accept, or comment via email/portal.
- Accepted quote → convert to invoice or subscription in one click.
- Create from Sales > Quotes > +New (and associate a project), or from inside a project.
- Can also quote a **one-time addon directly from a subscription** so the customer approves the price before invoicing.

### 5b. Subscriptions (the heart of the app)
- One record = one customer + one plan (+ addons, coupons), billed automatically.
- **Life cycle:** Trial → Live → (Upgrade/Downgrade anytime) → Non-renewing → Cancelled/Expired.
- **Create:** Sales > Subscriptions > +New → pick customer, product, plan, addons, coupons → Continue → Create.
- **Auto-invoicing:** subscription invoices generate automatically at **6 AM in your org's time zone** per the configured schedule.
- **Edit** to upgrade/downgrade existing or even cancelled subscriptions — proration (fair mid-cycle price adjustment) is automatic.
- Manage trials, cancellations, reactivations from here.
- **Metered/usage billing:** charge by usage or add usage charges on top of a base fee; define usage components + billing frequency and the workflow runs itself.

### 5c. Invoices
- **Two kinds:** auto-generated subscription invoices (each cycle) + manual one-time invoices.
- Statuses: Draft → Sent → Viewed → Partially Paid/Paid → Overdue → Void/Written off.
- Automated creation with precise tax calculation, custom branding, invoice consolidation, multi-currency, multilingual invoicing.
- Delivery: email, payment link, or customer portal. Overdue invoices trigger automatic reminders.

### 5d. Payments Received
- Every payment in one list: auto-charged card payments via gateways + manually recorded cash/cheque/bank transfers.
- Partial and bulk payments, multiple payment methods, automated reminders, payment links, hosted payment pages.
- Excess payments become customer credits for future invoices; refunds issued from here.

### 5e. Credit Notes
- Money you owe the customer — from downgrades, returns, or overcharges.
- Apply credit to next invoice(s) or refund as cash. Very common in subscriptions due to mid-cycle downgrades.

## MODULE 6: Expenses
- Record each expense: category, amount, tax, receipt attachment.
- **Billable expenses** → convert to invoices instantly; track team mileage → convert billable miles into reimbursements.
- Recurring expenses automated.
- Reports: spend by category, by customer, by project, mileage by employee — every line drills down to the individual expense.

## MODULE 7: Time Tracking (2 sub-modules)

### 7a. Projects
- One project per client engagement: billing method (fixed cost / hourly per project / per task / per staff), budget, tasks, assigned users.
- Send the customer a project quote first (accept/reject/comment) → after confirmation, convert to invoice.
- Project page tabs: **Expenses** (all project costs) and **Sales** (all its transactions); invoices raised as the project progresses.

### 7b. Timesheets
- Team logs hours against project tasks (manual entry or live timer).
- Billable hours → invoices, so hourly clients are billed accurately.
- Real-time monitoring of project hours and costs keeps you within budget.
- Optionally let customers view projects and timesheets in their portal.

## MODULE 8: Reports
- **Subscription metrics:** net revenue, MRR, churn rate, activations, cancellations; trials, aging, cash-flow projections, collections.
- **Categories:** Sales, Receivables, Payments, Subscriptions, Purchases & Expenses, Projects & Timesheets, Taxes, Activity/Audit.
- Customize by product or time period, combine data from multiple modules, print/export in various formats.
- Example of depth: Subscriptions Summary report filters by specific products and their plans.
- **Custom Schedulers:** automate recurring reports (e.g., monthly sales performance emailed to you).

## SETTINGS — not a "module," but the machinery
- **Preferences:** General, Customers, Items, Projects, Sales, Purchase sections — including which modules show in your sidebar.
- **Taxes:** tax preferences per item/contact → compliant transactions without manual math.
- **Templates & Branding:** customize quotes, invoice templates, portal invitation emails, payment receipts.
- **Payment Gateways:** connect Stripe/PayPal/Razorpay etc. for automatic card charging each cycle.
- **Hosted Payment Pages:** PCI-compliant ready-made checkout pages — customers pick and pay; no need to build your own payment webpages.
- **Dunning Management:** automated failed-payment recovery — retries, card-update requests, expiration alerts, failed-payment notifications; tracks recovery rate, revenue recovered, customers saved from involuntary churn.
- **Customer Portal:** customers see all their transactions; view/accept/comment on quotes; edit their info; share invoices; access timesheets and project details; manage subscriptions and update cards.
- **Email Notifications:** automated emails for every event — trial ending, renewal upcoming, payment failed, card expiring.
- **Automation (Workflows & Webhooks):** real-time updates on subscriptions/payments/invoices via webhooks; trigger-based custom workflows.
- **Users & Roles:** add staff with permission levels.

---

# QUICK REFERENCE TABLE — ZOHO BILLING

| # | Sidebar section | Sub-modules inside |
|---|---|---|
| 1 | Home | Dashboard |
| 2 | Customers | — |
| 3 | Product Catalog | Products, Plans, Addons, Coupons |
| 4 | Items | — |
| 5 | Sales | Quotes, Subscriptions, Invoices, Payments Received, Credit Notes |
| 6 | Expenses | Expenses (+ recurring expenses) |
| 7 | Time Tracking | Projects, Timesheets |
| 8 | Reports | 50+ built-in and custom reports |
| — | Settings | Taxes, Templates, Gateways, Hosted Pages, Dunning, Portal, Automation, Users |

---

# THE COMPLETE END-TO-END JOURNEY (ZOHO BILLING)

1. **Setup** — org details, taxes, payment gateway, branding (Settings).
2. **Catalog** — build Product → Plans → Addons → Coupons.
3. **Customer** — add customer → send Quote → customer accepts.
4. **Subscription** — subscription created (trial starts if configured).
5. **Auto-billing** — trial ends → invoice auto-generated at 6 AM → card auto-charged → payment recorded.
6. **Recovery** — card fails → Dunning retries and emails the customer to update the card.
7. **Self-service** — customer manages everything in their Portal.
8. **Changes** — mid-cycle upgrade/downgrade → proration + Credit Notes handled automatically.
9. **Services side** — meanwhile you track Expenses and Project hours and bill those too.
10. **Insight** — Reports show MRR, churn, receivables, and profit.

---

# ZOHO INVOICE vs ZOHO BILLING — KEY DIFFERENCE

| | Zoho Invoice | Zoho Billing |
|---|---|---|
| Billing style | One-time, manual (you create/send each invoice) | Automatic, repeating (system bills on schedule) |
| Best for | Freelancers, job-based work | SaaS, memberships, any recurring revenue |
| Price | Free | Paid plans |
| Subscriptions/Plans/Addons | No | Yes (core feature) |
| Dunning (failed-payment recovery) | No | Yes |
| Hosted checkout pages | No | Yes |
| Quotes, Invoices, Payments, Credit Notes | Yes | Yes |
| Expenses, Projects, Timesheets | Yes | Yes |
| MRR / churn analytics | No | Yes |

**In one paragraph:** Zoho Invoice = one-time, manual billing — you create and send each invoice; great for freelancers and job-based work, and it's free. Zoho Billing = automatic, repeating billing — you set up plans once, and the system creates invoices, charges cards, handles upgrades/downgrades, retries failed payments, and reports subscription metrics on its own. Both share the same Zoho organization, so Billing is essentially the "grown-up" version of Invoice for recurring revenue.

---

*Guide compiled from official Zoho Invoice and Zoho Billing documentation (zoho.com/invoice/help and zoho.com/billing/help), current as of July 2026.*