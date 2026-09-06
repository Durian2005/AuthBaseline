# -*- coding: utf-8 -*-
"""端到端冒烟测试：前端不改动后端，仅验证既有 API 契约仍被正确消费。"""
import json
import urllib.request
import urllib.error

BASE = 'http://localhost:5007'
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

PASS, FAIL = 0, 0


def call(path, body=None, method='POST'):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={'Content-Type': 'application/json'} if data else {}
    )
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode() or '{}')
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw or '{}')
        except Exception:
            return e.code, {}


def check(name, cond, extra=''):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  [PASS] {name}')
    else:
        FAIL += 1
        print(f'  [FAIL] {name} {extra}')


USER = 'smokeuser'
PW = 'Smoke1234'
PW2 = 'Smoke5678'

print('\n=== 1. 注册 ===')
s, d = call('/api/auth/register', {'username': USER, 'password': PW})
check('注册成功', s == 200 and d.get('success'), f'{s} {d}')
check('初始状态为 Pending', d.get('data', {}).get('status') == 'Pending', d)

print('\n=== 2. 口令复杂度 ===')
s, d = call('/api/auth/register', {'username': 'weakone', 'password': 'abc'})
check('弱口令被拒 (WEAK_PASSWORD)', s == 400 and d.get('code') == 'WEAK_PASSWORD', f'{s} {d}')
s, d = call('/api/auth/register', {'username': USER, 'password': PW})
check('重名被拒 (DUPLICATE_USERNAME)', s == 409 and d.get('code') == 'DUPLICATE_USERNAME', f'{s} {d}')

print('\n=== 3. 待审核拦截 ===')
s, d = call('/api/auth/login', {'username': USER, 'password': PW})
check('未审核不能登录 (PENDING_APPROVAL)', s == 401 and d.get('code') == 'PENDING_APPROVAL', f'{s} {d}')

print('\n=== 4. 审核 ===')
s, d = call('/api/auth/approve', {'username': USER, 'adminUsername': 'admin'})
check('审核通过', s == 200 and d.get('data', {}).get('status') == 'Enabled', f'{s} {d}')
s, d = call('/api/auth/login', {'username': USER, 'password': PW})
check('审核后可登录', s == 200 and d.get('success'), f'{s} {d}')

print('\n=== 5. 失败锁定 ===')
for i in range(1, 4):
    s, d = call('/api/auth/login', {'username': USER, 'password': 'WrongPass1'})
    if i < 3:
        check(f'第 {i} 次错误 (INVALID_CREDENTIALS)', s == 401 and d.get('code') == 'INVALID_CREDENTIALS', f'{s} {d}')
    else:
        check('第 3 次错误触发锁定 (ACCOUNT_LOCKED)', s == 401 and d.get('code') == 'ACCOUNT_LOCKED', f'{s} {d}')
        check('返回 lockoutEnd 供前端倒计时', bool(d.get('data', {}).get('lockoutEnd')), d)

s, d = call('/api/auth/login', {'username': USER, 'password': PW})
check('锁定期间正确口令也被拒', s == 401 and d.get('code') == 'ACCOUNT_LOCKED', f'{s} {d}')
check('返回 remainingSeconds', 'remainingSeconds' in (d.get('data') or {}), d)

print('\n=== 6. 解锁 ===')
s, d = call('/api/auth/unlock', {'username': USER, 'adminUsername': 'admin'})
check('管理员解锁成功', s == 200 and d.get('data', {}).get('status') == 'Enabled', f'{s} {d}')
s, d = call('/api/auth/login', {'username': USER, 'password': PW})
check('解锁后可登录', s == 200 and d.get('success'), f'{s} {d}')

print('\n=== 7. 修改口令 ===')
s, d = call('/api/auth/change-password', {'username': USER, 'oldPassword': 'BadOld123', 'newPassword': PW2})
check('旧口令错误被拒', s == 401 and d.get('code') == 'INVALID_CREDENTIALS', f'{s} {d}')
s, d = call('/api/auth/change-password', {'username': USER, 'oldPassword': PW, 'newPassword': PW2})
check('改密成功', s == 200 and d.get('success'), f'{s} {d}')
s, d = call('/api/auth/login', {'username': USER, 'password': PW})
check('旧口令立即失效', s == 401, f'{s} {d}')
s, d = call('/api/auth/login', {'username': USER, 'password': PW2})
check('新口令可登录', s == 200 and d.get('success'), f'{s} {d}')

print('\n=== 8. 管理员保护 ===')
s, d = call('/api/auth/delete-user', {'username': 'admin', 'adminUsername': 'admin'})
check('禁止注销管理员 (CANNOT_DELETE_ADMIN)', s == 400 and d.get('code') == 'CANNOT_DELETE_ADMIN', f'{s} {d}')
s, d = call('/api/auth/users', None, method='GET')
s2, d2 = call('/api/auth/users?adminUsername=nobody', None, method='GET')
check('非管理员无权限 (UNAUTHORIZED)', s2 == 401 and d2.get('code') == 'UNAUTHORIZED', f'{s2} {d2}')

print('\n=== 9. 注销用户 ===')
s, d = call('/api/auth/delete-user', {'username': USER, 'adminUsername': 'admin'})
check('注销成功', s == 200 and d.get('success'), f'{s} {d}')
s, d = call('/api/auth/users', {'x': 1}) if False else call('/api/auth/users?adminUsername=admin', None, method='GET')
check('用户列表中已移除', USER not in [u['username'] for u in d.get('data', [])], d)

print('\n=== 10. 审计日志 ===')
s, d = call('/api/auth/logs?adminUsername=admin', None, method='GET')
logs = d.get('data', [])
check('日志非空', len(logs) > 0, d)
check('日志含本轮操作', any(USER in (l.get('request') or '') for l in logs), '')
check('日志字段完整', all(
    k in logs[0] for k in ('operatorName', 'action', 'statusBefore', 'statusAfter', 'timestamp')
), logs[0] if logs else {})

print(f'\n===== 结果：{PASS} 通过 / {FAIL} 失败 =====\n')
