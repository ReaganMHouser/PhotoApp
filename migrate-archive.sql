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
