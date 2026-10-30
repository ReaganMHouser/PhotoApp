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
