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
