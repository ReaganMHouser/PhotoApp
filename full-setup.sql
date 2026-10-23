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
