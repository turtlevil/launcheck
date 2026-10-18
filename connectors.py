"""Read-only Slack/Gmail OAuth and targeted context retrieval for a *local single-owner* MVP.
No broad crawling, no third-party passwords. OAuth app registration is required.
"""
from __future__ import annotations
import base64
import os
import re
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlencode
import httpx
from cryptography.fernet import Fernet, InvalidToken

SLACK_SCOPES = 'channels:read,channels:history,users:read,users:read.email'
GMAIL_SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'


def cipher():
    key = os.getenv('CONNECTOR_ENCRYPTION_KEY')
    if not key:
        raise ValueError('Set CONNECTOR_ENCRYPTION_KEY before connecting accounts (see README).')
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid encryption key; generate a Fernet key as shown in README.') from exc


def configured(provider):
    if provider == 'slack':
        return bool(os.getenv('SLACK_CLIENT_ID') and os.getenv('SLACK_CLIENT_SECRET') and os.getenv('CONNECTOR_ENCRYPTION_KEY'))
    if provider == 'gmail':
        return bool(os.getenv('GOOGLE_CLIENT_ID') and os.getenv('GOOGLE_CLIENT_SECRET') and os.getenv('CONNECTOR_ENCRYPTION_KEY'))
    return False


def redirect_uri(provider):
    # Public deployments must use HTTPS and configure its exact redirect in the provider dashboard.
    base = os.getenv('LAUNCHCHECK_BASE_URL', 'http://127.0.0.1:8000').rstrip('/')
    return base + '/api/connectors/' + provider + '/callback'


def authorization_url(provider, state):
    if provider == 'slack':
        return 'https://slack.com/oauth/v2/authorize?' + urlencode({
            'client_id':os.environ['SLACK_CLIENT_ID'], 'scope':SLACK_SCOPES,
            'redirect_uri':redirect_uri(provider), 'state':state})
    return 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode({
        'client_id':os.environ['GOOGLE_CLIENT_ID'], 'redirect_uri':redirect_uri(provider),
        'response_type':'code', 'scope':GMAIL_SCOPES, 'access_type':'offline',
        'prompt':'consent', 'state':state})


def exchange(provider, code):
    with httpx.Client(timeout=16) as client:
        if provider == 'slack':
            res = client.post('https://slack.com/api/oauth.v2.access', data={
                'client_id':os.environ['SLACK_CLIENT_ID'], 'client_secret':os.environ['SLACK_CLIENT_SECRET'],
                'code':code, 'redirect_uri':redirect_uri(provider)})
            res.raise_for_status(); obj = res.json()
            if not obj.get('ok') or not obj.get('access_token'):
                raise ValueError('Slack authorization failed: ' + str(obj.get('error','unknown')))
            return {'access_token':obj['access_token'], 'label':obj.get('team',{}).get('name','Slack workspace'), 'refresh_token':'', 'expires_at':0}
        res = client.post('https://oauth2.googleapis.com/token', data={
            'client_id':os.environ['GOOGLE_CLIENT_ID'], 'client_secret':os.environ['GOOGLE_CLIENT_SECRET'],
            'code':code, 'redirect_uri':redirect_uri(provider), 'grant_type':'authorization_code'})
        res.raise_for_status(); obj=res.json()
        if not obj.get('access_token'):
            raise ValueError('Google authorization did not return an access token.')
        profile=client.get('https://gmail.googleapis.com/gmail/v1/users/me/profile', headers={'Authorization':'Bearer '+obj['access_token']})
        profile.raise_for_status()
        return {'access_token':obj['access_token'], 'refresh_token':obj.get('refresh_token',''),
            'expires_at':int(time.time()) + int(obj.get('expires_in',3600))-90,
            'label':profile.json().get('emailAddress','Gmail')}


def refresh_google(current):
    if not current.get('refresh_token'):
        raise ValueError('Gmail session expired. Disconnect and reconnect to authorize again.')
    response = httpx.post('https://oauth2.googleapis.com/token', data={
        'client_id':os.environ['GOOGLE_CLIENT_ID'], 'client_secret':os.environ['GOOGLE_CLIENT_SECRET'],
        'grant_type':'refresh_token', 'refresh_token':current['refresh_token']}, timeout=16)
    response.raise_for_status()
    obj=response.json()
    if not obj.get('access_token'):
        raise ValueError('Gmail token refresh failed. Reconnect the account.')
    return {**current,'access_token':obj['access_token'], 'expires_at':int(time.time())+int(obj.get('expires_in',3600))-90}


def decision_terms(decision):
    stop={'were','have','from','that','this','will','with','about','into','launch','launching','friday','monday','ready','our','the','and','for','are','next','client','going','product','we'}
    terms=[]
    for term in re.findall(r'[\w-]{3,}',decision.lower()):
        if term not in stop and term not in terms:
            terms.append(term)
    return terms[:5]


def fetch_slack_channels(token):
    """Only channels a bot has joined; users further select channels before sync."""
    r=httpx.get('https://slack.com/api/conversations.list', headers={'Authorization':'Bearer '+token},
        params={'types':'public_channel','exclude_archived':'true','limit':100}, timeout=16)
    r.raise_for_status(); data=r.json()
    if not data.get('ok'):
        raise ValueError('Slack channel list failed: '+str(data.get('error')))
    return [{'id':x['id'],'name':x.get('name',''),'is_member':x.get('is_member',False)}
        for x in data.get('channels',[]) if x.get('is_member')]


def fetch_slack_messages(token, channels, terms):
    """One page per selected channel, capped to limit API calls/data. Read-only."""
    results=[]
    earliest=str(int((datetime.now(timezone.utc)-timedelta(days=30)).timestamp()))
    for channel in channels[:3]:
        r=httpx.get('https://slack.com/api/conversations.history', headers={'Authorization':'Bearer '+token},
            params={'channel':channel['id'],'limit':15,'oldest':earliest}, timeout=16)
        r.raise_for_status(); obj=r.json()
        if not obj.get('ok'):
            raise ValueError('Slack history failed for #'+channel['name']+': '+str(obj.get('error')))
        lines=[]
        for m in obj.get('messages',[]):
            raw=m.get('text','')
            if not raw or (terms and not any(t in raw.lower() for t in terms)):
                continue
            lines.append(f"[{datetime.fromtimestamp(float(m.get('ts',0)),timezone.utc).isoformat()}] {m.get('user','team member')}: {raw[:1100]}")
        if lines:
            results.append({'provider':'slack', 'external_id':channel['id'],
                            'filename':'slack-#'+channel['name']+'.txt', 'kind':'Slack',
                            'content':'#'+channel['name']+'\n'+'\n'.join(lines)})
    return results



def fetch_slack_members(token):
    """Fetch a reviewable directory, not private messages. Slack must grant both users scopes."""
    results=[]
    cursor=None
    for _ in range(15):  # bounded pagination; enough for a hackathon workspace
        params={'limit':200}
        if cursor: params['cursor']=cursor
        r=httpx.get('https://slack.com/api/users.list',
            headers={'Authorization':'Bearer '+token}, params=params, timeout=16)
        r.raise_for_status()
        data=r.json()
        if not data.get('ok'):
            raise ValueError('Slack member directory failed: '+str(data.get('error','unknown')))
        for member in data.get('members',[]):
            profile=member.get('profile') or {}
            email=(profile.get('email') or '').lower().strip()
            if not email or member.get('deleted') or member.get('is_bot') or member.get('is_app_user') or member.get('id')=='USLACKBOT':
                continue
            name=member.get('real_name') or profile.get('real_name') or member.get('name') or email
            results.append({'slack_id':member['id'],'name':name[:100], 'email':email[:200]})
        cursor=(data.get('response_metadata') or {}).get('next_cursor')
        if not cursor: break
    return results


def gmail_plain_text(payload):
    chunks=[]
    def visit(part):
        if len(chunks)>5: return
        content_type=part.get('mimeType','')
        if content_type=='text/plain':
            raw=part.get('body',{}).get('data','')
            if raw:
                try:
                    chunks.append(base64.urlsafe_b64decode(raw + '='*((-len(raw))%4)).decode('utf-8',errors='replace'))
                except Exception: pass
        for sub in part.get('parts',[]): visit(sub)
    visit(payload)
    return '\n'.join(chunks)[:2500]


def fetch_gmail_messages(token, terms):
    # Search only recent mail relevant to the user's own chosen project, not their whole mailbox.
    query='newer_than:30d ' + ('{'+' '.join(terms[:4])+'}' if terms else 'subject:launch')
    headers={'Authorization':'Bearer '+token}
    with httpx.Client(timeout=16) as client:
        r=client.get('https://gmail.googleapis.com/gmail/v1/users/me/messages',headers=headers,
           params={'q':query,'maxResults':12})
        r.raise_for_status()
        ids=r.json().get('messages',[])
        sources=[]
        for item in ids[:12]:
            resp=client.get('https://gmail.googleapis.com/gmail/v1/users/me/messages/'+item['id'],headers=headers,
                           params={'format':'full'})
            resp.raise_for_status(); msg=resp.json()
            hdrs={x['name'].lower():x.get('value','') for x in msg.get('payload',{}).get('headers',[])}
            body=gmail_plain_text(msg.get('payload',{})) or msg.get('snippet','')
            if not body and not hdrs.get('subject'): continue
            content=f"Date: {hdrs.get('date','')}\nFrom: {hdrs.get('from','')}\nTo: {hdrs.get('to','')}\nSubject: {hdrs.get('subject','')}\n\n{body}"
            sources.append({'provider':'gmail','external_id':item['id'],
                            'filename':'gmail-'+item['id'][:14]+'.eml','kind':'Email','content':content[:4000]})
    return sources


# Per-employee explicit OAuth: no workspace-wide read, no DMs or private channels.
# Slack user tokens are distinct from the existing owner bot token.
def employee_redirect_uri(provider):
    return os.getenv('LAUNCHCHECK_BASE_URL','http://127.0.0.1:8000').rstrip('/') + '/api/team/connectors/' + provider + '/callback'


def employee_authorization_url(provider,state):
    if provider=='slack':
        return 'https://slack.com/oauth/v2/authorize?' + urlencode({
            'client_id':os.environ['SLACK_CLIENT_ID'],
            'user_scope':'channels:read,channels:history',
            'redirect_uri':employee_redirect_uri(provider),'state':state})
    return 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode({
        'client_id':os.environ['GOOGLE_CLIENT_ID'],'redirect_uri':employee_redirect_uri(provider),
        'response_type':'code','scope':GMAIL_SCOPES,
        'access_type':'offline','prompt':'consent','state':state})


def employee_exchange(provider,code):
    if provider=='gmail':
        with httpx.Client(timeout=16) as client:
            res=client.post('https://oauth2.googleapis.com/token',data={
                'client_id':os.environ['GOOGLE_CLIENT_ID'],
                'client_secret':os.environ['GOOGLE_CLIENT_SECRET'],'code':code,
                'redirect_uri':employee_redirect_uri(provider),'grant_type':'authorization_code'})
            res.raise_for_status();obj=res.json()
            if not obj.get('access_token'):raise ValueError('Google authorization failed')
            profile=client.get('https://gmail.googleapis.com/gmail/v1/users/me/profile',
                headers={'Authorization':'Bearer '+obj['access_token']})
            profile.raise_for_status()
            return {'access_token':obj['access_token'],
                'refresh_token':obj.get('refresh_token',''),
                'expires_at':int(time.time())+int(obj.get('expires_in',3600))-90,
                'label':profile.json().get('emailAddress','')}
    with httpx.Client(timeout=16) as client:
        res=client.post('https://slack.com/api/oauth.v2.access',data={
            'client_id':os.environ['SLACK_CLIENT_ID'],
            'client_secret':os.environ['SLACK_CLIENT_SECRET'],'code':code,
            'redirect_uri':employee_redirect_uri(provider)})
        res.raise_for_status();obj=res.json()
        token=obj.get('authed_user',{}).get('access_token')
        if not obj.get('ok') or not token:
            raise ValueError('Slack did not return a per-user token. Check user scopes.')
        probe=client.get('https://slack.com/api/auth.test',headers={'Authorization':'Bearer '+token})
        probe.raise_for_status(); identity=probe.json()
        if not identity.get('ok'):raise ValueError('Could not verify Slack user identity')
        return {'access_token':token,'refresh_token':'','expires_at':0,
                'label':identity.get('user','Slack user')+' @ '+identity.get('team','Slack workspace')}
