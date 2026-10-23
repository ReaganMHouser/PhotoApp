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
