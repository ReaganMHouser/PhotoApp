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
