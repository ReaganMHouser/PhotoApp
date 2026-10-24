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
