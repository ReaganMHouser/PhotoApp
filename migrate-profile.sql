-- Photo Journal: synced profile header (safe to run more than once)
create table if not exists public.profiles (
  user_id uuid primary key default auth.uid() references auth.users(id) on delete cascade,
  title text,
  bio text,
  updated_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
drop policy if exists "profile own select" on public.profiles;
drop policy if exists "profile own insert" on public.profiles;
drop policy if exists "profile own update" on public.profiles;
create policy "profile own select" on public.profiles for select to authenticated using (user_id = auth.uid());
create policy "profile own insert" on public.profiles for insert to authenticated with check (user_id = auth.uid());
create policy "profile own update" on public.profiles for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
grant select, insert, update on public.profiles to authenticated;
