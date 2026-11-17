-- Fractured SMP: Supabase schema. Run once in the Supabase SQL editor.
-- Before running: Authentication > Providers > Email > turn on "Confirm email".
create extension if not exists pgcrypto with schema extensions;

-- ---------- Tables ----------
create table public.admins(user_id uuid primary key references auth.users on delete cascade, joined_at timestamptz default now());
create table public.invitations(token_hash text primary key, created_by uuid, expires_at timestamptz not null, used_by uuid, used_at timestamptz);
create table public.content_published(key text primary key, data jsonb not null, version int not null default 1, published_by uuid, published_at timestamptz default now());
create table public.content_drafts(key text primary key, data jsonb not null, updated_by uuid, updated_at timestamptz default now());
create table public.change_history(id bigint generated always as identity primary key, key text not null,
  action text not null check (action in ('draft','published','discarded','restored')),
  admin_id uuid, admin_email text, summary text, snapshot jsonb, at timestamptz default now());
create table public.reaction_events(post_id text not null, emoji text not null, visitor uuid not null, primary key(post_id,emoji,visitor));
-- content keys used by the site: site, members, episodes, news, story

-- ---------- Helpers ----------
create function public.is_admin() returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.admins where user_id = auth.uid()) $$;

-- ---------- Row Level Security ----------
alter table public.admins enable row level security;
alter table public.invitations enable row level security;      -- no policies: only the functions below touch it
alter table public.content_published enable row level security;
alter table public.content_drafts enable row level security;
alter table public.change_history enable row level security;
alter table public.reaction_events enable row level security;  -- no policies: only react()/get_reactions()

create policy "anyone reads published" on public.content_published for select using (true);
create policy "admins read drafts"     on public.content_drafts    for select using (public.is_admin());
create policy "admins read history"    on public.change_history    for select using (public.is_admin());
create policy "admins read admins"     on public.admins            for select using (public.is_admin());
-- No insert/update/delete policies exist: every write goes through the functions below,
-- so nothing reaches the public site without publish_draft(), and every change is logged.
-- All admins pass the same is_admin() check, so all four have identical permissions.

-- ---------- Drafts, publish, history, restore ----------
create function public.save_draft(p_key text, p_data jsonb, p_summary text default null) returns void
language plpgsql security definer set search_path=public as $$
begin
  if not is_admin() then raise exception 'not authorised'; end if;
  insert into content_drafts(key,data,updated_by) values(p_key,p_data,auth.uid())
    on conflict(key) do update set data=excluded.data, updated_by=excluded.updated_by, updated_at=now();
  insert into change_history(key,action,admin_id,admin_email,summary,snapshot)
    values(p_key,'draft',auth.uid(),auth.jwt()->>'email',p_summary,p_data);
end $$;

create function public.publish_draft(p_key text, p_summary text default null) returns void
language plpgsql security definer set search_path=public as $$
declare d jsonb;
begin
  if not is_admin() then raise exception 'not authorised'; end if;
  select data into d from content_drafts where key=p_key;
  if d is null then raise exception 'no draft for %', p_key; end if;
  insert into content_published(key,data,published_by) values(p_key,d,auth.uid())
    on conflict(key) do update set data=excluded.data, version=content_published.version+1,
      published_by=excluded.published_by, published_at=now();
  delete from content_drafts where key=p_key;
  insert into change_history(key,action,admin_id,admin_email,summary,snapshot)
    values(p_key,'published',auth.uid(),auth.jwt()->>'email',p_summary,d);
end $$;

create function public.discard_draft(p_key text) returns void
language plpgsql security definer set search_path=public as $$
declare d jsonb;
begin
  if not is_admin() then raise exception 'not authorised'; end if;
  select data into d from content_drafts where key=p_key;
  delete from content_drafts where key=p_key;
  insert into change_history(key,action,admin_id,admin_email,summary,snapshot)
    values(p_key,'discarded',auth.uid(),auth.jwt()->>'email','Draft discarded',d);
end $$;

-- Restoring publishes an old snapshot as a NEW version; later history is never erased.
create function public.restore_version(p_history_id bigint) returns void
language plpgsql security definer set search_path=public as $$
declare h change_history;
begin
  if not is_admin() then raise exception 'not authorised'; end if;
  select * into h from change_history where id=p_history_id and action in ('published','restored');
  if not found then raise exception 'not a published version'; end if;
  insert into content_published(key,data,published_by) values(h.key,h.snapshot,auth.uid())
    on conflict(key) do update set data=excluded.data, version=content_published.version+1,
      published_by=excluded.published_by, published_at=now();
  insert into change_history(key,action,admin_id,admin_email,summary,snapshot)
    values(h.key,'restored',auth.uid(),auth.jwt()->>'email','Restored version from history #'||p_history_id,h.snapshot);
end $$;

-- ---------- Invitations (single-use, expiring, stored hashed) ----------
create function public.create_invite(p_days int default 7) returns text
language plpgsql security definer set search_path=public,extensions as $$
declare t text;
begin
  if not (is_admin() or session_user in ('postgres','supabase_admin')) then raise exception 'not authorised'; end if;
  t := encode(gen_random_bytes(24),'hex');
  insert into invitations(token_hash,created_by,expires_at)
    values(encode(digest(t,'sha256'),'hex'), auth.uid(), now()+make_interval(days=>p_days));
  return t;   -- shown once; only the hash is stored
end $$;

-- Called by the signed-in invitee after confirming their email. No manual approval needed.
create function public.claim_invite(p_token text) returns void
language plpgsql security definer set search_path=public,extensions as $$
declare ok boolean;
begin
  if auth.uid() is null then raise exception 'sign in first'; end if;
  select email_confirmed_at is not null into ok from auth.users where id=auth.uid();
  if not coalesce(ok,false) then raise exception 'verify your email first'; end if;
  if (select count(*) from admins) >= 4 then raise exception 'admin limit reached'; end if;
  update invitations set used_by=auth.uid(), used_at=now()
    where token_hash=encode(digest(p_token,'sha256'),'hex') and used_at is null and expires_at>now();
  if not found then raise exception 'invalid or expired invitation'; end if;
  insert into admins(user_id) values(auth.uid()) on conflict do nothing;
end $$;

revoke execute on function public.save_draft(text,jsonb,text), public.publish_draft(text,text),
  public.discard_draft(text), public.restore_version(bigint), public.create_invite(int),
  public.claim_invite(text) from public, anon;

-- ---------- Shared emoji reactions (visitors, no login) ----------
create function public.react(p_post text, p_emoji text, p_visitor uuid, p_on boolean) returns void
language plpgsql security definer set search_path=public as $$
begin
  if p_emoji not in ('🔥','💜','👍','😮','😂') or length(p_post)>64 then raise exception 'invalid reaction'; end if;
  if p_on then insert into reaction_events values(p_post,p_emoji,p_visitor) on conflict do nothing;
  else delete from reaction_events where post_id=p_post and emoji=p_emoji and visitor=p_visitor; end if;
end $$;

create function public.get_reactions() returns table(post_id text, emoji text, n int)
language sql stable security definer set search_path=public
as $$ select post_id, emoji, count(*)::int from reaction_events group by 1,2 $$;

-- ---------- Image storage (public read, admin-only write) ----------
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
  values('media','media',true,5242880,array['image/jpeg','image/png','image/webp','image/gif'])
  on conflict(id) do nothing;
create policy "admins manage media" on storage.objects for all
  using (bucket_id='media' and public.is_admin()) with check (bucket_id='media' and public.is_admin());

-- ---------- First four invitations ----------
-- Run this line in the SQL editor (not on the website), then send each token privately:
-- select public.create_invite(7) from generate_series(1,4);
