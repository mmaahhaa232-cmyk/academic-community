-- مجتمعي الأكاديمي | إعداد قاعدة البيانات الآمنة في Supabase
-- نفّذي هذا الملف مرة واحدة من Supabase > SQL Editor > New query.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  email text,
  researcher_type text not null default 'باحث',
  specialty text,
  affiliation text,
  academic_title text,
  orcid_url text,
  scholar_url text,
  bio text,
  membership_status text not null default 'pending'
    check (membership_status in ('pending','approved','rejected')),
  account_role text not null default 'member'
    check (account_role in ('member','admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- دوال آمنة لتجنّب تكرار سياسات RLS على جدول profiles.
create or replace function public.is_community_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and account_role = 'admin'
      and membership_status = 'approved'
  );
$$;

create or replace function public.is_approved_member()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and membership_status = 'approved'
  );
$$;

create or replace function public.create_profile_for_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (
    id, full_name, email, researcher_type, specialty, affiliation,
    academic_title, orcid_url, scholar_url, bio
  ) values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name',''),
    new.email,
    coalesce(new.raw_user_meta_data->>'researcher_type','باحث'),
    nullif(new.raw_user_meta_data->>'specialty',''),
    nullif(new.raw_user_meta_data->>'affiliation',''),
    nullif(new.raw_user_meta_data->>'academic_title',''),
    nullif(new.raw_user_meta_data->>'orcid_url',''),
    nullif(new.raw_user_meta_data->>'scholar_url',''),
    nullif(new.raw_user_meta_data->>'bio','')
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
after insert on auth.users
for each row execute procedure public.create_profile_for_new_user();

-- منع المستخدم من اعتماد عضويته أو منح نفسه صلاحية مسؤول.
create or replace function public.protect_profile_permissions()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if auth.uid() = old.id and not public.is_community_admin() then
    if new.membership_status is distinct from old.membership_status
       or new.account_role is distinct from old.account_role then
      raise exception 'لا يمكن تغيير حالة العضوية أو صلاحية الحساب ذاتيًا';
    end if;
    if new.id is distinct from old.id then
      raise exception 'لا يمكن تغيير معرّف الحساب';
    end if;
  end if;
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists protect_profile_permissions_trigger on public.profiles;
create trigger protect_profile_permissions_trigger
before update on public.profiles
for each row execute function public.protect_profile_permissions();

create table if not exists public.community_items (
  id uuid primary key default gen_random_uuid(),
  category text not null
    check (category in ('researchers','teams','library','events','ideas')),
  title text not null,
  details jsonb not null default '{}'::jsonb,
  owner_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.touch_community_item()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists touch_community_item_trigger on public.community_items;
create trigger touch_community_item_trigger
before update on public.community_items
for each row execute function public.touch_community_item();

alter table public.profiles enable row level security;
alter table public.community_items enable row level security;

drop policy if exists "profile_read_self_or_approved" on public.profiles;
create policy "profile_read_self_or_approved"
on public.profiles for select to authenticated
using (
  id = auth.uid()
  or public.is_community_admin()
  or (membership_status = 'approved' and public.is_approved_member())
);

drop policy if exists "profile_update_self_or_admin" on public.profiles;
create policy "profile_update_self_or_admin"
on public.profiles for update to authenticated
using (id = auth.uid() or public.is_community_admin())
with check (id = auth.uid() or public.is_community_admin());

drop policy if exists "items_read_approved_members" on public.community_items;
create policy "items_read_approved_members"
on public.community_items for select to authenticated
using (public.is_approved_member());

drop policy if exists "items_insert_approved_owner" on public.community_items;
create policy "items_insert_approved_owner"
on public.community_items for insert to authenticated
with check (owner_id = auth.uid() and public.is_approved_member());

drop policy if exists "items_update_owner_or_admin" on public.community_items;
create policy "items_update_owner_or_admin"
on public.community_items for update to authenticated
using (owner_id = auth.uid() or public.is_community_admin())
with check (owner_id = auth.uid() or public.is_community_admin());

drop policy if exists "items_delete_owner_or_admin" on public.community_items;
create policy "items_delete_owner_or_admin"
on public.community_items for delete to authenticated
using (owner_id = auth.uid() or public.is_community_admin());

grant usage on schema public to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.community_items to authenticated;

-- بعد إنشاء أول حساب لك والتحقق من بريده، اجعليه حساب المسؤول من SQL Editor:
-- update public.profiles
-- set account_role = 'admin', membership_status = 'approved'
-- where email = 'YOUR_EMAIL@example.com';
--
-- لاعتماد عضو بعد مراجعة طلبه:
-- update public.profiles set membership_status = 'approved'
-- where email = 'MEMBER_EMAIL@example.com';
--
-- لا تضعي مفتاح service_role في ملفات الموقع أو GitHub.
