-- Photo Journal: categories / collections (safe to run more than once)
alter table public.posts add column if not exists categories text[] not null default '{}';
create index if not exists posts_categories_gin on public.posts using gin (categories);
