-- PHOTO JOURNAL: complete database setup. Safe to run more than once.

-- ===== 1. Posts table, photo storage, permissions =====
-- Photo Journal: run once in Supabase → SQL Editor
create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  caption text not null default '',
  created_at timestamptz not null default now(),
  image_path text not null
);
create index if not exists posts_user_created on public.posts(user_id, created_at desc);
alter table public.posts enable row level security;
drop policy if exists "own select" on public.posts;
drop policy if exists "own insert" on public.posts;
drop policy if exists "own update" on public.posts;
drop policy if exists "own delete" on public.posts;
create policy "own select" on public.posts for select to authenticated using (user_id = auth.uid());
create policy "own insert" on public.posts for insert to authenticated with check (user_id = auth.uid());
create policy "own update" on public.posts for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "own delete" on public.posts for delete to authenticated using (user_id = auth.uid());

-- Private bucket; files stored as <user_id>/<uuid>.jpg
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('photos','photos', false, 10485760, array['image/jpeg'])
on conflict (id) do update set public = false;
drop policy if exists "photos own read" on storage.objects;
drop policy if exists "photos own insert" on storage.objects;
drop policy if exists "photos own update" on storage.objects;
drop policy if exists "photos own delete" on storage.objects;
create policy "photos own read" on storage.objects for select to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "photos own insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "photos own update" on storage.objects for update to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "photos own delete" on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text);

-- Let signed-in users use their rows (RLS still limits them to their own)
grant select, insert, update, delete on public.posts to authenticated;

-- ===== 2. Multi-photo posts (up to 8) =====
-- Photo Journal: multi-photo posts (safe to run more than once)
alter table public.posts add column if not exists image_paths text[] not null default '{}';
update public.posts set image_paths = array[image_path]
  where (image_paths is null or cardinality(image_paths) = 0) and image_path is not null;
-- image_path stays as "first photo" for backward compatibility; allow null for future flexibility
alter table public.posts alter column image_path drop not null;
-- 1 to 8 photos per post (added only if missing)
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'posts_image_paths_1_to_8') then
    alter table public.posts add constraint posts_image_paths_1_to_8
      check (cardinality(image_paths) between 1 and 8);
  end if;
end $$;

-- ===== 3. Profile title and bio =====
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

-- ===== 4. Categories (collections) =====
-- Photo Journal: categories / collections (safe to run more than once)
alter table public.posts add column if not exists categories text[] not null default '{}';
create index if not exists posts_categories_gin on public.posts using gin (categories);

-- ===== 5. Read-only share link =====
-- Photo Journal: read-only share link (safe to run more than once)
-- Design: visitors (anon) can NOT read any table directly. They only get data through two
-- SECURITY DEFINER functions that require an enabled, exactly-matching, long token.
-- Photos: anon may only *sign* (not list/download/upload/delete) a file that is used by a
-- post of a user whose sharing is ON. Turning sharing off stops new signed URLs at once;
-- links already handed out expire within 10 minutes (the app signs viewer links for 10 min).

-- 1) Columns on profiles (owner-only RLS from migrate-profile.sql still applies)
alter table public.profiles add column if not exists share_token text;
alter table public.profiles add column if not exists share_enabled boolean not null default false;
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_share_token_key') then
    alter table public.profiles add constraint profiles_share_token_key unique (share_token);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'profiles_share_token_len') then
    alter table public.profiles add constraint profiles_share_token_len
      check (share_token is null or length(share_token) >= 32);
  end if;
end $$;
-- columns the shared feed reads (no-ops if earlier migrations ran)
alter table public.posts add column if not exists image_paths text[] not null default '{}';
alter table public.posts add column if not exists categories text[] not null default '{}';

-- 2) Read functions for visitors. They return nothing unless sharing is ON and the token matches.
create or replace function public.get_shared_profile(p_token text)
returns table (title text, bio text, post_count bigint)
language sql stable security definer set search_path = ''
as $$
  select pr.title, pr.bio,
         (select count(*) from public.posts p where p.user_id = pr.user_id)
  from public.profiles pr
  where p_token is not null and length(p_token) >= 32
    and pr.share_enabled and pr.share_token = p_token;
$$;

create or replace function public.get_shared_posts(p_token text)
returns table (id uuid, caption text, created_at timestamptz, image_path text, image_paths text[], categories text[])
language sql stable security definer set search_path = ''
as $$
  select p.id, p.caption, p.created_at, p.image_path, p.image_paths, p.categories
  from public.posts p
  join public.profiles pr on pr.user_id = p.user_id
  where p_token is not null and length(p_token) >= 32
    and pr.share_enabled and pr.share_token = p_token
  order by p.created_at desc;
$$;

revoke all on function public.get_shared_profile(text) from public;
revoke all on function public.get_shared_posts(text) from public;
grant execute on function public.get_shared_profile(text) to anon, authenticated;
grant execute on function public.get_shared_posts(text) to anon, authenticated;

-- 3) Photo check used by the storage policy. Kept in a schema the API does not expose,
--    so it can't be called directly over the web.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to anon, authenticated;
create or replace function private.is_shared_photo(p_name text)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1
    from public.posts p
    join public.profiles pr on pr.user_id = p.user_id
    where pr.share_enabled and pr.share_token is not null
      and (storage.foldername(p_name))[1] = p.user_id::text
      and (p_name = p.image_path or p_name = any (p.image_paths))
  );
$$;
revoke all on function private.is_shared_photo(text) from public;
grant execute on function private.is_shared_photo(text) to anon, authenticated;

-- 4) Storage: visitors may only create signed URLs for shared photos (no listing, no download
--    without a signed URL, no writes). Owner policies from setup.sql are untouched.
drop policy if exists "photos shared sign" on storage.objects;
do $$ begin
  if exists (select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
             where n.nspname = 'storage' and p.proname = 'allow_any_operation') then
    execute $p$create policy "photos shared sign" on storage.objects for select to anon
      using (bucket_id = 'photos'
             and storage.allow_any_operation(array['storage.object.sign','storage.object.sign_many'])
             and private.is_shared_photo(name))$p$;
  else
    -- older storage version without operation helpers: still limited to shared photos only
    raise notice 'storage.allow_any_operation not found; sharing policy will not restrict by operation';
    execute $p$create policy "photos shared sign" on storage.objects for select to anon
      using (bucket_id = 'photos' and private.is_shared_photo(name))$p$;
  end if;
end $$;
