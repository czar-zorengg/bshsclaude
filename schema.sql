-- ============================================================
-- BSHS LOST AND FOUND HUB
-- Full database schema, indexes, RLS policies, triggers, storage
-- Paste this ENTIRE file into Supabase -> SQL Editor -> New Query -> Run
-- Safe to re-run on the same project (uses IF NOT EXISTS / DROP POLICY IF EXISTS).
-- ============================================================

create extension if not exists pgcrypto;

-- ============================================================
-- 1. TABLES
-- ============================================================

-- Profile table linked 1:1 to Supabase Auth users (auth.users).
-- We never store passwords here -- Supabase Auth handles that.
create table if not exists public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  student_id text unique,
  full_name text not null,
  email text unique not null,
  role text not null default 'student' check (role in ('student','admin')),
  created_at timestamptz default now()
);

create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  -- References public.users (not auth.users directly) so PostgREST can
  -- automatically embed profile info (name, student id) in joined queries.
  student_id uuid references public.users(id) on delete set null,
  report_type text not null check (report_type in ('Lost Item','Found Item')),
  item_name text not null,
  category text not null,
  location text not null,
  item_date date not null,
  description text not null,
  photo_url text,
  status text not null default 'Pending' check (status in ('Pending','Approved','Rejected','Claimed','Resolved')),
  created_at timestamptz default now()
);

create table if not exists public.claim_requests (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.users(id) on delete cascade,
  report_id uuid not null references public.reports(id) on delete cascade,
  message text,
  status text not null default 'Pending' check (status in ('Pending','Approved','Rejected','Completed')),
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

-- ============================================================
-- 2. INDEXES
-- ============================================================

create index if not exists reports_student_idx on public.reports(student_id);
create index if not exists reports_status_idx on public.reports(status);
create index if not exists reports_report_type_idx on public.reports(report_type);
create index if not exists reports_created_at_idx on public.reports(created_at);

create index if not exists claim_requests_student_idx on public.claim_requests(student_id);
create index if not exists claim_requests_report_idx on public.claim_requests(report_id);
create index if not exists claim_requests_status_idx on public.claim_requests(status);

-- ============================================================
-- 3. HELPER FUNCTIONS
-- ============================================================

-- Returns true if the currently-authenticated user is an admin.
-- SECURITY DEFINER lets it read public.users even though RLS is on,
-- which avoids infinite-recursion problems in the RLS policies below.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.users where id = auth.uid() and role = 'admin'
  );
$$;

-- Aggregate, non-identifying counts for the public homepage stats section.
-- Safe to expose to anonymous visitors: no row-level data, just counts.
create or replace function public.get_public_stats()
returns table (
  total_reports bigint,
  found_items bigint,
  pending_reports bigint,
  claimed_items bigint
)
language sql
security definer
set search_path = public
stable
as $$
  select
    (select count(*) from public.reports) as total_reports,
    (select count(*) from public.reports where report_type = 'Found Item' and status = 'Approved') as found_items,
    (select count(*) from public.reports where status = 'Pending') as pending_reports,
    (select count(*) from public.reports where status = 'Claimed') as claimed_items;
$$;

grant execute on function public.get_public_stats() to anon, authenticated;

-- ============================================================
-- 4. TRIGGERS
-- ============================================================

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_claim_requests_updated_at on public.claim_requests;
create trigger trg_claim_requests_updated_at
before update on public.claim_requests
for each row execute function public.set_updated_at();

-- When an admin approves a claim, automatically mark the related report Claimed.
create or replace function public.handle_claim_approval()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status = 'Approved' and old.status is distinct from 'Approved' then
    update public.reports set status = 'Claimed' where id = new.report_id;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_handle_claim_approval on public.claim_requests;
create trigger trg_handle_claim_approval
after update on public.claim_requests
for each row execute function public.handle_claim_approval();

-- ============================================================
-- 5. ENABLE ROW LEVEL SECURITY
-- ============================================================

alter table public.users enable row level security;
alter table public.reports enable row level security;
alter table public.claim_requests enable row level security;

-- ============================================================
-- 6. USERS POLICIES
-- ============================================================

drop policy if exists "users_select_own_or_admin" on public.users;
create policy "users_select_own_or_admin"
on public.users for select
to authenticated
using (auth.uid() = id or public.is_admin());

drop policy if exists "users_insert_own" on public.users;
create policy "users_insert_own"
on public.users for insert
to authenticated
with check (auth.uid() = id);

drop policy if exists "users_update_own_or_admin" on public.users;
create policy "users_update_own_or_admin"
on public.users for update
to authenticated
using (auth.uid() = id or public.is_admin())
with check (auth.uid() = id or public.is_admin());

-- ============================================================
-- 7. REPORTS POLICIES
-- ============================================================

-- Logged-in students may insert a report only under their own account.
drop policy if exists "reports_insert_own" on public.reports;
create policy "reports_insert_own"
on public.reports for insert
to authenticated
with check (auth.uid() = student_id);

-- Anyone (including anonymous visitors) may view Approved Found Item reports.
drop policy if exists "reports_select_public_approved_found" on public.reports;
create policy "reports_select_public_approved_found"
on public.reports for select
to anon, authenticated
using (status = 'Approved' and report_type = 'Found Item');

-- Students may view their own reports regardless of status.
drop policy if exists "reports_select_own" on public.reports;
create policy "reports_select_own"
on public.reports for select
to authenticated
using (auth.uid() = student_id);

-- Admins may view every report.
drop policy if exists "reports_select_admin" on public.reports;
create policy "reports_select_admin"
on public.reports for select
to authenticated
using (public.is_admin());

-- Only admins may update reports (approve / reject / change status).
drop policy if exists "reports_update_admin" on public.reports;
create policy "reports_update_admin"
on public.reports for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

-- ============================================================
-- 8. CLAIM_REQUESTS POLICIES
-- ============================================================

drop policy if exists "claims_insert_own" on public.claim_requests;
create policy "claims_insert_own"
on public.claim_requests for insert
to authenticated
with check (auth.uid() = student_id);

drop policy if exists "claims_select_own" on public.claim_requests;
create policy "claims_select_own"
on public.claim_requests for select
to authenticated
using (auth.uid() = student_id);

drop policy if exists "claims_select_admin" on public.claim_requests;
create policy "claims_select_admin"
on public.claim_requests for select
to authenticated
using (public.is_admin());

-- Only admins may update claim requests (approve / reject).
drop policy if exists "claims_update_admin" on public.claim_requests;
create policy "claims_update_admin"
on public.claim_requests for update
to authenticated
using (public.is_admin())
with check (public.is_admin());

-- ============================================================
-- 9. STORAGE BUCKET FOR REPORT PHOTOS
-- ============================================================

insert into storage.buckets (id, name, public)
values ('report-photos', 'report-photos', true)
on conflict (id) do nothing;

-- Any logged-in student may upload a photo into this bucket.
drop policy if exists "report_photos_insert_authenticated" on storage.objects;
create policy "report_photos_insert_authenticated"
on storage.objects for insert
to authenticated
with check (bucket_id = 'report-photos');

-- The bucket is public so item photos can be shown on the Items page
-- via a plain public URL (no signed URLs needed).
drop policy if exists "report_photos_read_public" on storage.objects;
create policy "report_photos_read_public"
on storage.objects for select
to anon, authenticated
using (bucket_id = 'report-photos');

-- ============================================================
-- DONE. Next: create your first admin account.
-- 1. Register a normal account on student-register.html.
-- 2. In Supabase -> Table Editor -> users, find your row.
-- 3. Change its "role" cell from student to admin. Save.
-- 4. Log in at admin-login.html with the same email/password.
-- ============================================================
