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

-- ===== 6. Archive =====
-- Photo Journal: archive (hide posts from the page without deleting). Safe to run more than once.
alter table public.posts add column if not exists archived boolean not null default false;
create index if not exists posts_user_archived_created on public.posts (user_id, archived, created_at desc);

-- Re-create the sharing functions so visitors never get archived posts or their photos.
-- Same security as before: security definer, empty search_path, no public execute.
create or replace function public.get_shared_profile(p_token text)
returns table (title text, bio text, post_count bigint)
language sql stable security definer set search_path = ''
as $$
  select pr.title, pr.bio,
         (select count(*) from public.posts p where p.user_id = pr.user_id and not p.archived)
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
    and not p.archived
  order by p.created_at desc;
$$;

revoke all on function public.get_shared_profile(text) from public;
revoke all on function public.get_shared_posts(text) from public;
grant execute on function public.get_shared_profile(text) to anon, authenticated;
grant execute on function public.get_shared_posts(text) to anon, authenticated;

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
      and not p.archived
      and (storage.foldername(p_name))[1] = p.user_id::text
      and (p_name = p.image_path or p_name = any (p.image_paths))
  );
$$;
revoke all on function private.is_shared_photo(text) from public;
grant execute on function private.is_shared_photo(text) to anon, authenticated;
-- The visitor storage rule "photos shared sign" (from migrate-sharing.sql) calls
-- private.is_shared_photo, so it picks up the archived filter automatically.

-- ===== 7. Shared with me =====
-- Photo Journal: "Shared with me" (journals you've opened via someone's share link). Safe to run more than once.
-- Needs migrate-sharing.sql and migrate-archive.sql first (included in full-setup.sql).
alter table public.posts add column if not exists archived boolean not null default false;

create table if not exists public.shared_views (
  viewer_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  share_token text not null,
  last_viewed_at timestamptz not null default now(),
  primary key (viewer_id, share_token)
);
alter table public.shared_views enable row level security;
drop policy if exists "shared_views own select" on public.shared_views;
drop policy if exists "shared_views own insert" on public.shared_views;
drop policy if exists "shared_views own update" on public.shared_views;
drop policy if exists "shared_views own delete" on public.shared_views;
create policy "shared_views own select" on public.shared_views for select to authenticated using (viewer_id = auth.uid());
create policy "shared_views own insert" on public.shared_views for insert to authenticated with check (viewer_id = auth.uid());
create policy "shared_views own update" on public.shared_views for update to authenticated using (viewer_id = auth.uid()) with check (viewer_id = auth.uid());
create policy "shared_views own delete" on public.shared_views for delete to authenticated using (viewer_id = auth.uid());
revoke all on public.shared_views from anon;
grant select, insert, update, delete on public.shared_views to authenticated;

-- Record a visit. Only for signed-in users, only for a currently enabled link, never your own.
-- Returns true when saved, false otherwise (bad/disabled link or your own page).
create or replace function public.record_shared_view(p_token text)
returns boolean
language plpgsql volatile security definer set search_path = ''
as $$
declare uid uuid := auth.uid();
begin
  if uid is null or p_token is null or length(p_token) < 32 then return false; end if;
  if not exists (select 1 from public.profiles pr
                 where pr.share_enabled and pr.share_token = p_token and pr.user_id <> uid) then
    return false;
  end if;
  insert into public.shared_views (viewer_id, share_token, last_viewed_at)
  values (uid, p_token, now())
  on conflict (viewer_id, share_token) do update set last_viewed_at = excluded.last_viewed_at;
  return true;
end;
$$;

-- Your list. Only rows whose link is still enabled and unchanged; never returns owner id/email.
create or replace function public.get_my_shared_journals()
returns table (share_token text, title text, post_count bigint, cover_path text, last_viewed_at timestamptz)
language sql stable security definer set search_path = ''
as $$
  select v.share_token,
         pr.title,
         (select count(*) from public.posts p where p.user_id = pr.user_id and not p.archived),
         (select coalesce(nullif(p.image_paths[1], ''), p.image_path)
            from public.posts p
           where p.user_id = pr.user_id and not p.archived
           order by p.created_at desc limit 1),
         v.last_viewed_at
  from public.shared_views v
  join public.profiles pr on pr.share_token = v.share_token and pr.share_enabled
  where auth.uid() is not null and v.viewer_id = auth.uid() and pr.user_id <> auth.uid()
  order by v.last_viewed_at desc;
$$;

revoke all on function public.record_shared_view(text) from public;
revoke all on function public.get_my_shared_journals() from public;
revoke all on function public.record_shared_view(text) from anon;
revoke all on function public.get_my_shared_journals() from anon;
grant execute on function public.record_shared_view(text) to authenticated;
grant execute on function public.get_my_shared_journals() to authenticated;

-- Covers in the list are signed by signed-in users, so the visitor photo rule now covers
-- both anon and authenticated. It still only allows signing photos of non-archived posts
-- whose owner has sharing on (private.is_shared_photo); owners' own rules are unchanged.
drop policy if exists "photos shared sign" on storage.objects;
do $$ begin
  if exists (select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
             where n.nspname = 'storage' and p.proname = 'allow_any_operation') then
    execute $p$create policy "photos shared sign" on storage.objects for select to anon, authenticated
      using (bucket_id = 'photos'
             and storage.allow_any_operation(array['storage.object.sign','storage.object.sign_many'])
             and private.is_shared_photo(name))$p$;
  else
    raise notice 'storage.allow_any_operation not found; sharing policy will not restrict by operation';
    execute $p$create policy "photos shared sign" on storage.objects for select to anon, authenticated
      using (bucket_id = 'photos' and private.is_shared_photo(name))$p$;
  end if;
end $$;

-- ===== 8. Private nicknames for Shared with me =====
-- Photo Journal: private nicknames for journals in "Shared with me". Safe to run more than once.
-- Needs migrate-shared-with-me.sql first (included in full-setup.sql).
alter table public.shared_views add column if not exists nickname text;
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'shared_views_nickname_len') then
    alter table public.shared_views add constraint shared_views_nickname_len
      check (nickname is null or char_length(nickname) between 1 and 40);
  end if;
end $$;

-- Set or clear (empty/blank -> null = use original name) the caller's own nickname for a saved journal.
-- Only touches the caller's own row; returns true if a row was updated.
create or replace function public.rename_shared_journal(p_token text, p_nickname text)
returns boolean
language plpgsql volatile security definer set search_path = ''
as $$
declare uid uuid := auth.uid(); n text; cnt int;
begin
  if uid is null or p_token is null then return false; end if;
  n := nullif(left(btrim(regexp_replace(coalesce(p_nickname, ''), '\s+', ' ', 'g')), 40), '');
  update public.shared_views set nickname = n
   where viewer_id = uid and share_token = p_token;
  get diagnostics cnt = row_count;
  return cnt > 0;
end;
$$;
revoke all on function public.rename_shared_journal(text, text) from public;
revoke all on function public.rename_shared_journal(text, text) from anon;
grant execute on function public.rename_shared_journal(text, text) to authenticated;

-- Return the nickname with the list (return type changes, so drop and re-create).
drop function if exists public.get_my_shared_journals();
create function public.get_my_shared_journals()
returns table (share_token text, title text, post_count bigint, cover_path text, last_viewed_at timestamptz, nickname text)
language sql stable security definer set search_path = ''
as $$
  select v.share_token,
         pr.title,
         (select count(*) from public.posts p where p.user_id = pr.user_id and not p.archived),
         (select coalesce(nullif(p.image_paths[1], ''), p.image_path)
            from public.posts p
           where p.user_id = pr.user_id and not p.archived
           order by p.created_at desc limit 1),
         v.last_viewed_at,
         v.nickname
  from public.shared_views v
  join public.profiles pr on pr.share_token = v.share_token and pr.share_enabled
  where auth.uid() is not null and v.viewer_id = auth.uid() and pr.user_id <> auth.uid()
  order by v.last_viewed_at desc;
$$;
revoke all on function public.get_my_shared_journals() from public;
revoke all on function public.get_my_shared_journals() from anon;
grant execute on function public.get_my_shared_journals() to authenticated;
-- record_shared_view only updates last_viewed_at on conflict, so re-visiting keeps the nickname.

-- ===== 9. Private custom covers for Shared with me =====
-- Photo Journal: private custom covers for journals in "Shared with me". Safe to run more than once.
-- Needs migrate-sharing.sql, migrate-archive.sql, migrate-shared-with-me.sql and
-- migrate-rename-shared.sql first (all included in full-setup.sql).
alter table public.shared_views add column if not exists nickname text;
alter table public.shared_views add column if not exists cover_path text;        -- viewer's own upload: <viewer_id>/covers/<uuid>.jpg
alter table public.shared_views add column if not exists cover_owner_path text;  -- one of the owner's shared photos

-- Set the caller's cover for one saved journal. p_kind: 'upload' | 'post' | 'default'.
-- Only touches the caller's own row. Returns true when saved.
create or replace function public.set_shared_cover(p_token text, p_kind text, p_path text)
returns boolean
language plpgsql volatile security definer set search_path = ''
as $$
declare uid uuid := auth.uid(); cnt int;
begin
  if uid is null or p_token is null then return false; end if;
  if p_kind = 'default' then
    update public.shared_views set cover_path = null, cover_owner_path = null
     where viewer_id = uid and share_token = p_token;
  elsif p_kind = 'upload' then
    -- must be a file in the caller's own covers folder
    if p_path is null or p_path not like uid::text || '/covers/%' or p_path like '%..%'
       or array_length(storage.foldername(p_path), 1) <> 2 then
      return false;
    end if;
    update public.shared_views set cover_path = p_path, cover_owner_path = null
     where viewer_id = uid and share_token = p_token;
  elsif p_kind = 'post' then
    -- must be a photo of a currently shared, non-archived post of THIS link's owner
    if p_path is null or not exists (
         select 1 from public.profiles pr
          where pr.share_enabled and pr.share_token = p_token and pr.user_id <> uid
            and (storage.foldername(p_path))[1] = pr.user_id::text)
       or not private.is_shared_photo(p_path) then
      return false;
    end if;
    update public.shared_views set cover_owner_path = p_path, cover_path = null
     where viewer_id = uid and share_token = p_token;
  else
    return false;
  end if;
  get diagnostics cnt = row_count;
  return cnt > 0;
end;
$$;
revoke all on function public.set_shared_cover(text, text, text) from public;
revoke all on function public.set_shared_cover(text, text, text) from anon;
grant execute on function public.set_shared_cover(text, text, text) to authenticated;

-- List: adds my_cover_path (viewer upload) and owner_cover_path (only while that photo is still
-- shared by this owner and its post isn't archived/deleted; otherwise null -> default cover).
drop function if exists public.get_my_shared_journals();
create function public.get_my_shared_journals()
returns table (share_token text, title text, post_count bigint, cover_path text, last_viewed_at timestamptz,
               nickname text, my_cover_path text, owner_cover_path text)
language sql stable security definer set search_path = ''
as $$
  select v.share_token,
         pr.title,
         (select count(*) from public.posts p where p.user_id = pr.user_id and not p.archived),
         (select coalesce(nullif(p.image_paths[1], ''), p.image_path)
            from public.posts p
           where p.user_id = pr.user_id and not p.archived
           order by p.created_at desc limit 1),
         v.last_viewed_at,
         v.nickname,
         v.cover_path,
         case when v.cover_owner_path is not null
               and (storage.foldername(v.cover_owner_path))[1] = pr.user_id::text
               and private.is_shared_photo(v.cover_owner_path)
              then v.cover_owner_path end
  from public.shared_views v
  join public.profiles pr on pr.share_token = v.share_token and pr.share_enabled
  where auth.uid() is not null and v.viewer_id = auth.uid() and pr.user_id <> auth.uid()
  order by v.last_viewed_at desc;
$$;
revoke all on function public.get_my_shared_journals() from public;
revoke all on function public.get_my_shared_journals() from anon;
grant execute on function public.get_my_shared_journals() to authenticated;

-- Notes:
-- * record_shared_view only updates last_viewed_at on conflict, so covers and nicknames are kept.
-- * Owner-photo covers are signed through the existing "photos shared sign" storage rule
--   (anon + authenticated, via private.is_shared_photo), so sharing off / link reset / archived
--   or deleted posts stop them working immediately; the app then shows the default cover.
-- * Viewer uploads live in the viewer's own folder and use the existing owner storage rules.
