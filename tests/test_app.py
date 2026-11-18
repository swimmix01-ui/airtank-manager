import json, re, sys, threading, http.server, functools, datetime, urllib.parse, os
from playwright.sync_api import sync_playwright

ROOT = sys.argv[1]
SHOTS = sys.argv[2]
os.makedirs(SHOTS, exist_ok=True)
PORT = 8765

# ── static server ──
class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(('127.0.0.1', PORT), functools.partial(Quiet, directory=ROOT))
threading.Thread(target=srv.serve_forever, daemon=True).start()

# ── mock Firestore ──
def enc(v):
    if v is None: return {'nullValue': None}
    if isinstance(v, bool): return {'booleanValue': v}
    if isinstance(v, int): return {'integerValue': str(v)}
    if isinstance(v, float): return {'doubleValue': v}
    return {'stringValue': str(v)}
def dec(f):
    out = {}
    for k, v in (f or {}).items():
        if 'stringValue' in v: out[k] = v['stringValue']
        elif 'integerValue' in v: out[k] = int(v['integerValue'])
        elif 'doubleValue' in v: out[k] = v['doubleValue']
        elif 'booleanValue' in v: out[k] = v['booleanValue']
        elif 'nullValue' in v: out[k] = None
    return out

XSS = '<img src=x onerror=alert(1)>'
store = {
 'tanks': {
  'T1': {'id': 'SCU-001', 'vol': '80Cuft / 11.1L / 200Bar', 'purpose': 'diving', 'maxP': 200, 'pressure': 120, 'location': '구조정', 'introduceYear': 2019, 'lastInspDate': '2024-03-01', 'lastChargeDate': '2026-11-01'},
  'T2': {'id': 'SCU-002', 'vol': '80', 'maxP': 200, 'pressure': 200, 'location': '건조창고', 'introduceYear': 2012, 'lastInspDate': '2023-12-01', 'lastChargeDate': '2026-10-01'},
  'T3': {'id': XSS, 'vol': '"><script>alert(2)</script>', 'maxP': 300, 'pressure': 280, 'location': "구조정'); alert('3", 'introduceYear': 2020, 'lastInspDate': '', 'lastChargeDate': '2026-11-15'},
  'T4': {'id': 'MED-01', 'vol': '2L / 150Bar', 'purpose': 'medical', 'maxP': 150, 'pressure': 140, 'location': '특장차', 'introduceYear': 2022, 'lastInspDate': '2025-01-10', 'lastChargeDate': '2026-11-12'},
  'T5': {'id': 'FIRE-07', 'vol': '6.8L / 300Bar', 'purpose': 'fire', 'maxP': 300, 'pressure': 300, 'location': '스타리아', 'introduceYear': 2016, 'lastInspDate': '2021-11-01', 'lastChargeDate': '2026-11-14'},
  'T6': {'id': 'SCU-006', 'vol': '106', 'maxP': 300, 'pressure': 0, 'location': '', 'introduceYear': 0, 'lastInspDate': '', 'lastChargeDate': ''},
  'T7': {'id': 'SCU-007', 'vol': '63Cuft / 9.0L / 200Bar', 'purpose': 'diving', 'maxP': 200, 'pressure': 210, 'location': '야외창고', 'mfgDate': '2018-05', 'lastInspDate': '2023-06-01', 'lastChargeDate': '2026-11-10'},
 },
 'charges': {
  'C1': {'tankId': 'SCU-001', 'date': '2026-11-01T01:00:00.000Z', 'pressure': 200, 'usage': '해상수색', 'charger': '최선근', 'note': '<script>alert(4)</script>'},
  'C2': {'tankId': 'SCU-001', 'date': '2026-10-02T03:00:00.000Z', 'pressure': 195, 'usage': '장비점검', 'charger': '홍길동', 'note': ''},
  'C3': {'tankId': 'SCU-002', 'date': '2026-10-01T05:00:00.000Z', 'pressure': 200, 'usage': '선저검사', 'charger': XSS, 'note': ''},
  'C4': {'tankId': 'MED-01', 'date': '2026-11-12T06:00:00.000Z', 'pressure': 150, 'usage': '실제구조대응', 'charger': '김대원', 'note': ''},
  'C5': {'tankId': 'FIRE-07', 'date': '2026-11-14T06:00:00.000Z', 'pressure': 300, 'usage': '수중수색훈련', 'charger': '김대원', 'note': ''},
 },
 'inspections': {
  'I1': {'tankId': 'SCU-001', 'date': '2024-03-01', 'org': '한국가스안전공사', 'result': '합격', 'note': ''},
 },
 'config': {}
}
commits, reqlog = [], []
state = {'fail401': 0, 'deny403': False, 'token_n': 0, 'pw': 'pass1234'}
PAGE = 3
ROOTNAME = 'projects/airssat/databases/(default)/documents/'

def handle_fs(route, request):
    url = request.url
    auth = request.headers.get('authorization', '')
    reqlog.append((request.method, url.split('documents')[-1][:60], auth[:20]))
    if not auth.startswith('Bearer tok'):
        return route.fulfill(status=403, json={'error': {'status': 'PERMISSION_DENIED', 'message': 'no auth'}})
    if state['fail401'] > 0:
        state['fail401'] -= 1
        return route.fulfill(status=401, json={'error': {'status': 'UNAUTHENTICATED', 'message': 'expired'}})
    if state['deny403']:
        return route.fulfill(status=403, json={'error': {'status': 'PERMISSION_DENIED', 'message': 'denied'}})
    path = urllib.parse.urlparse(url).path.split('/documents', 1)[1]
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    if request.method == 'POST' and path == ':commit':
        body = json.loads(request.post_data)
        writes = body['writes']
        # validate all first (atomic)
        for w in writes:
            name = w.get('update', {}).get('name') or w.get('delete')
            col, did = name.replace(ROOTNAME, '').split('/')
            exists = did in store[col]
            cd = w.get('currentDocument')
            if cd and cd.get('exists') is False and exists:
                return route.fulfill(status=409, json={'error': {'status': 'ALREADY_EXISTS', 'message': 'exists'}})
            if cd and cd.get('exists') is True and not exists:
                return route.fulfill(status=404, json={'error': {'status': 'NOT_FOUND', 'message': 'nf'}})
        for w in writes:
            if 'delete' in w:
                col, did = w['delete'].replace(ROOTNAME, '').split('/'); store[col].pop(did, None)
            else:
                col, did = w['update']['name'].replace(ROOTNAME, '').split('/')
                data = dec(w['update']['fields'])
                if 'updateMask' in w:
                    doc = store[col].setdefault(did, {})
                    for k in w['updateMask']['fieldPaths']:
                        if k in data: doc[k] = data[k]
                        else: doc.pop(k, None)
                else:
                    store[col][did] = data
        commits.append(body)
        return route.fulfill(status=200, json={'writeResults': [{} for _ in writes]})
    parts = [p for p in path.split('/') if p]
    if request.method == 'GET' and len(parts) == 1:
        col = parts[0]; items = sorted(store[col].items())
        start = int(qs.get('pageToken', ['0'])[0]); chunk = items[start:start + PAGE]
        res = {'documents': [{'name': ROOTNAME + col + '/' + k, 'fields': {kk: enc(vv) for kk, vv in v.items()}} for k, v in chunk]}
        if start + PAGE < len(items): res['nextPageToken'] = str(start + PAGE)
        if not chunk: res = {}
        return route.fulfill(status=200, json=res)
    if request.method == 'GET' and len(parts) == 2:
        col, did = parts
        if did not in store.get(col, {}): return route.fulfill(status=404, json={'error': {'status': 'NOT_FOUND', 'message': 'nf'}})
        return route.fulfill(status=200, json={'name': ROOTNAME + col + '/' + did, 'fields': {k: enc(v) for k, v in store[col][did].items()}})
    route.fulfill(status=400, json={'error': {'message': 'bad'}})

def tok():
    state['token_n'] += 1; return 'tok%d' % state['token_n']
def handle_idt(route, request):
    url = request.url; body = json.loads(request.post_data or '{}')
    if 'signInWithPassword' in url:
        if body.get('email') in ('test@kcg.kr','rescue.pohang@airssat.app') and body.get('password') == state['pw']:
            return route.fulfill(json={'idToken': tok(), 'refreshToken': 'r1', 'expiresIn': '3600', 'localId': 'uid1', 'email': body.get('email','test@kcg.kr')})
        return route.fulfill(status=400, json={'error': {'message': 'INVALID_LOGIN_CREDENTIALS'}})
    if 'accounts:update' in url:
        state['pw'] = body['password']
        return route.fulfill(json={'idToken': tok(), 'refreshToken': 'r2', 'expiresIn': '3600', 'localId': 'uid1', 'email': body.get('email','test@kcg.kr')})
    route.fulfill(status=400, json={'error': {'message': 'UNKNOWN'}})
def handle_sts(route, request):
    route.fulfill(json={'id_token': tok(), 'refresh_token': 'r1', 'expires_in': '3600', 'user_id': 'uid1'})

results = []
def check(name, cond, info=''):
    results.append((name, bool(cond), info)); print(('PASS ' if cond else 'FAIL ') + name + ('' if cond else '  -> ' + str(info)))

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(bypass_csp=True, viewport={'width': 390, 'height': 844}, device_scale_factor=2, timezone_id='Asia/Seoul', locale='ko-KR', service_workers='block')
    ctx.route(re.compile(r'https://firestore\.googleapis\.com/.*'), handle_fs)
    ctx.route(re.compile(r'https://identitytoolkit\.googleapis\.com/.*'), handle_idt)
    ctx.route(re.compile(r'https://securetoken\.googleapis\.com/.*'), handle_sts)
    ctx.route(re.compile(r'https://fonts\.(googleapis|gstatic)\.com/.*'), lambda r, q: r.fulfill(status=200, body='', content_type='text/css'))
    xlsx_js = open('/tmp/xlsx.full.min.js').read() if os.path.exists('/tmp/xlsx.full.min.js') else None
    ctx.route(re.compile(r'https://cdnjs\.cloudflare\.com/.*'), lambda r, q: r.fulfill(status=200, body=xlsx_js, content_type='application/javascript') if (xlsx_js and 'xlsx' in q.url) else r.abort())
    page = ctx.new_page()
    page.clock.set_fixed_time(datetime.datetime(2026, 11, 18, 7, 30, tzinfo=datetime.timezone(datetime.timedelta(hours=9))))
    alerts, errors, dialogs = [], [], []
    def on_dialog(d):
        dialogs.append((d.type, d.message))
        if d.type == 'alert': alerts.append(d.message); d.dismiss()
        elif d.type == 'prompt': d.accept(state.get('prompt', ''))
        else: d.accept()
    page.on('dialog', on_dialog)
    page.on('pageerror', lambda e: errors.append(str(e)))
    page.on('console', lambda m: errors.append('console:' + m.text) if m.type == 'error' else None)
    toast = lambda: page.locator('#toast').inner_text()

    page.goto(f'http://127.0.0.1:{PORT}/index.html')
    page.wait_for_selector('#login:not(.hidden)', state='attached')
    page.screenshot(path=f'{SHOTS}/01_login.png')
    check('email field hidden (password only)', page.locator('#loginEmail').is_hidden())
    # wrong password
    page.fill('#loginPw', 'wrong'); page.click('#loginBtn')
    page.wait_for_function("document.getElementById('loginErr').textContent.length>0")
    check('wrong password rejected', '올바르지' in page.inner_text('#loginErr'), page.inner_text('#loginErr'))
    page.fill('#loginPw', 'pass1234'); page.click('#loginBtn')
    page.wait_for_selector('#login.hidden', state='attached'); page.wait_for_function("document.getElementById('connText').textContent!=='연결중'")
    page.wait_for_timeout(400)
    # expire popup shown once
    check('expire popup shown after login', page.locator('#mList.show').count() == 1)
    page.screenshot(path=f'{SHOTS}/02_expire_popup.png')
    page.click('#mList [data-action=close] >> nth=0'); page.wait_for_timeout(200)
    check('pagination loaded all 7 tanks', page.locator('.stat .val').first.inner_text() == '7', page.locator('.stat .val').first.inner_text())
    check('bottom nav = 현황/용기/검사이력/충전이력', page.locator('nav.bottom .nav-btn').all_inner_texts() == ['현황', '용기', '검사이력', '충전이력'], page.locator('nav.bottom .nav-btn').all_inner_texts())
    check('header has 스캔/설정', page.locator('header .hbtn').all_inner_texts() == ['스캔', '설정'], page.locator('header .hbtn').all_inner_texts())
    check('date is local (KST)', '2026년 11월 18일' in page.inner_text('#heroDate'), page.inner_text('#heroDate'))
    check('monthly chart rendered', page.locator('#chartMonthly .bar').count() == 6)
    check('donut rendered', page.locator('#chartDonut circle').count() >= 2)
    page.screenshot(path=f'{SHOTS}/03_dashboard.png', full_page=True)

    # stat vs popup consistency
    for cat in ['airExp', 'insp', 'pLow', 'airSoon']:
        n = int(page.locator(f'.stat[data-cat={cat}] .val').inner_text())
        if n:
            page.click(f'.stat[data-cat={cat}]'); page.wait_for_selector('#mList.show')
            m = page.locator('#lBody .tank').count(); page.keyboard.press('Escape'); page.wait_for_timeout(150)
            check(f'stat/popup consistent: {cat}', m == n, f'{n} vs {m}')
    # tanks page + XSS
    page.click('nav [data-page=tanks]'); page.wait_for_timeout(200)
    check('XSS id rendered as text', page.locator('#tankList .tank-id', has_text='<img src=x').count() == 1)
    page.screenshot(path=f'{SHOTS}/04_tanks.png', full_page=True)
    # filter: medical
    page.click('#chipsTankPur [data-val=medical]'); check('purpose filter', page.locator('#tankList .tank').count() == 1)
    page.click('#chipsTankPur [data-val=all]')
    page.fill('#tankSearch', 'scu-00'); page.wait_for_timeout(300); check('search case-insensitive', page.locator('#tankList .tank').count() == 4, page.locator('#tankList .tank').count())
    page.fill('#tankSearch', ''); page.wait_for_timeout(300)

    # detail of XSS tank
    page.locator('#tankList .tank', has_text='<img src=x').click(); page.wait_for_selector('#mDetail.show')
    page.screenshot(path=f'{SHOTS}/05_detail_xss.png', full_page=False)
    page.keyboard.press('Escape'); page.wait_for_timeout(200)

    # medical tank pressure 140/150 should NOT be low at 75%
    t4 = page.locator('#tankList .tank', has_text='MED-01')
    check('medical 140/150 not low', '압력부족' not in t4.inner_text())

    # ── charge flow with location change (the revert bug) at 07:30 KST
    page.click('header [data-page=scan]'); page.fill('#manualId', 'scu-001'); page.keyboard.press('Enter')
    page.wait_for_selector('#chargeForm:not(.hidden)', state='attached')
    page.select_option('#cUsage', '수중수색훈련'); page.select_option('#cLoc', '특장차')
    page.fill('#cPost', '200'); page.fill('#cCharger', '최선근')
    page.screenshot(path=f'{SHOTS}/06_charge_form.png', full_page=True)
    n0 = len(commits); page.click('#saveChargeBtn'); page.wait_for_function("document.getElementById('chargeForm').classList.contains('hidden')")
    c = commits[-1]['writes'] if len(commits) > n0 else []
    check('charge = single atomic commit (2 writes)', len(commits) == n0 + 1 and len(c) == 2, c)
    t1 = store['tanks']['T1']
    check('tank pressure/lastChargeDate NOT reverted', t1['pressure'] == 200 and t1['lastChargeDate'] == '2026-11-18' and t1['location'] == '특장차', t1)
    newc = [v for k, v in store['charges'].items() if k not in ('C1', 'C2', 'C3', 'C4', 'C5')]
    check('charge record saved with KST date', newc and newc[0]['date'].startswith('2026-11-17T22:30'), newc)
    upd = [w for w in c if 'updateMask' in w]
    check('tank update sends only changed fields', upd and set(upd[0]['updateMask']['fieldPaths']) == {'location', 'pressure', 'lastChargeDate', 'updatedAt', 'updatedBy'}, upd and upd[0]['updateMask'])

    # unregistered tank
    page.fill('#manualId', 'NEW-999'); page.click('[data-action=manualLookup]')
    check('unregistered tank -> register prompt', page.locator('[data-action=registerScanned]').count() == 1)
    page.click('[data-action=registerScanned]'); page.wait_for_selector('#mTank.show')
    check('register form prefilled id', page.input_value('#fId') == 'NEW-999')
    page.select_option('#fPurpose', 'diving'); page.select_option('#fVol', '0')
    check('maxP auto 300 for 106cuft', page.input_value('#fMaxP') == '300')
    page.fill('#fPressure', '250'); page.select_option('#fLoc', '구조정'); page.fill('#fMfg', '2021-03')
    page.screenshot(path=f'{SHOTS}/07_tank_form.png', full_page=False)
    page.click('#saveTankBtn'); page.wait_for_selector('#mTank:not(.show)', state='attached')
    check('new tank created', any(v['id'] == 'NEW-999' for v in store['tanks'].values()))
    check('after register, charge form shown', page.locator('#chargeForm:not(.hidden)').count() == 1)
    page.click('[data-action=cancelCharge]')

    # duplicate id
    page.click('nav [data-page=tanks]'); page.click('[data-action=addTank]'); page.wait_for_selector('#mTank.show')
    page.fill('#fId', 'scu-001'); page.select_option('#fPurpose', 'diving'); page.select_option('#fVol', '1'); page.click('#saveTankBtn'); page.wait_for_timeout(200)
    check('duplicate id rejected', '이미 등록' in toast(), toast())
    page.keyboard.press('Escape'); page.wait_for_timeout(200)

    # ── history: edit custom usage preserved
    page.click('nav [data-page=history]'); page.wait_for_timeout(200)
    page.screenshot(path=f'{SHOTS}/08_history.png', full_page=True)
    check('history XSS note escaped', page.locator('#histList', has_text='<script>alert(4)</script>').count() == 1)
    page.click('#histList [data-action=editCharge][data-cid=C1]'); page.wait_for_selector('#mCharge.show')
    check('custom usage loaded into 기타', page.input_value('#ceUsage') == '기타' and page.input_value('#ceUsageEtc') == '해상수색')
    page.fill('#ceNote', '수정됨'); n0 = len(commits); page.click('#saveCeBtn'); page.wait_for_selector('#mCharge:not(.show)', state='attached')
    check('custom usage kept after edit', store['charges']['C1']['usage'] == '해상수색' and store['charges']['C1']['note'] == '수정됨', store['charges']['C1'])
    um = commits[-1]['writes'][0]['updateMask']['fieldPaths']
    check('charge edit sends only changed fields', set(um) == {'note', 'updatedAt', 'updatedBy'}, um)

    # delete the newest charge of SCU-001 -> tank lastChargeDate reverts to C1 (2026-11-01)
    newid = [k for k, v in store['charges'].items() if v['tankId'] == 'SCU-001' and v['date'].startswith('2026-11-17')][0]
    page.click(f'#histList [data-action=deleteCharge][data-cid="{newid}"]'); page.wait_for_timeout(400)
    check('delete latest charge reverts tank date', store['tanks']['T1']['lastChargeDate'] == '2026-11-01' and newid not in store['charges'], store['tanks']['T1'])

    # ── tank edit: only location changed
    page.click('nav [data-page=tanks]'); page.locator('#tankList .tank', has_text='SCU-002').click(); page.wait_for_selector('#mDetail.show')
    page.click('#mDetail [data-action=editTank]'); page.wait_for_selector('#mTank.show')
    check('legacy vol preserved option', page.input_value('#fVol') == '__keep')
    page.select_option('#fLoc', '야외창고'); n0 = len(commits); page.click('#saveTankBtn'); page.wait_for_selector('#mDetail.show')
    um = commits[-1]['writes'][0]['updateMask']['fieldPaths']
    check('tank edit only sends changed fields', set(um) == {'location', 'updatedAt', 'updatedBy'}, um)
    check('legacy vol unchanged', store['tanks']['T2']['vol'] == '80')

    # ── send for inspection, then record 불합격
    page.click('#mDetail [data-action=toggleSend]'); page.wait_for_timeout(300)
    check('sending flag set', store['tanks']['T2'].get('sendingInsp') is True and store['tanks']['T2']['sendingInspDate'] == '2026-11-18')
    check('charge button disabled while sending', page.locator('#mDetail [data-action=chargeFromDetail][disabled]').count() == 1)
    page.click('#mDetail [data-action=openInsp]'); page.wait_for_selector('#mInsp.show')
    check('insp default date local', page.input_value('#iDate') == '2026-11-18', page.input_value('#iDate'))
    page.select_option('#iResult', '불합격'); page.fill('#iOrg', '한국가스안전공사'); page.click('#saveInspBtn'); page.wait_for_selector('#mDetail.show')
    t2 = store['tanks']['T2']
    check('불합격 -> inspFailed, sending cleared', t2.get('inspFailed') is True and t2.get('sendingInsp') is False and t2['lastInspDate'] == '2026-11-18', t2)
    page.screenshot(path=f'{SHOTS}/09_detail_failed.png', full_page=True)
    page.keyboard.press('Escape'); page.wait_for_timeout(200)
    page.click('header [data-page=scan]'); page.fill('#manualId', 'SCU-002'); page.keyboard.press('Enter'); page.wait_for_timeout(200)
    check('failed tank cannot be charged', page.locator('#chargeForm.hidden').count() == 1 and '충전할 수 없습니다' in page.inner_text('#scanResult'))

    # ── 401 → refresh → retry
    state['fail401'] = 1; n0 = state['token_n']
    page.click('[data-action=syncNow] >> nth=0'); page.wait_for_timeout(800)
    check('401 triggers token refresh and retry', state['token_n'] > n0 and page.inner_text('#connText') != '오프라인', (state['token_n'], n0, page.inner_text('#connText')))

    # ── 검사이력 (5-year bars)
    page.click('nav [data-page=schedule]'); page.wait_for_timeout(200)
    page.screenshot(path=f'{SHOTS}/10_schedule.png', full_page=True)
    bars = page.locator('#inspBars button.bar')
    check('inspection page shows overdue + 5 year bars', bars.count() == 6, bars.count())
    check('inspection page has no air-expiry content', '공기 만료' not in page.inner_text('#page-schedule'))
    n_over = int(page.locator('#inspBars button.bar[data-key=over] b').inner_text())
    page.click('#inspBars button.bar[data-key=over]'); page.wait_for_selector('#mList.show')
    check('overdue bar lists same number of tanks', page.locator('#lBody .item').count() == n_over and n_over > 0, (n_over, page.locator('#lBody .item').count()))
    page.screenshot(path=f'{SHOTS}/11_inspbar.png'); page.keyboard.press('Escape'); page.wait_for_timeout(150)
    page.click('#inspBars button.bar[data-key="2028"]'); page.wait_for_selector('#mList.show')
    check('2028 bar includes SCU-007 (2028-05-01)', 'SCU-007' in page.inner_text('#lBody') and '2028-05-01' in page.inner_text('#lBody'), page.inner_text('#lBody'))
    page.keyboard.press('Escape'); page.wait_for_timeout(150)
    card = page.locator('#schList .tank', has_text='FIRE-07').inner_text()
    check('FIRE-07 next insp 2026-01-01 overdue', '2026-01-01' in card and '초과' in card, card)
    check('inspection records listed', page.locator('#inspRecList .item').count() >= 2)

    # ── 충전이력 (monthly calendar)
    page.click('nav [data-page=history]'); page.wait_for_timeout(200)
    page.screenshot(path=f'{SHOTS}/16_charge_cal.png', full_page=True)
    days = page.locator('#chargeCal .cal-d[data-action=calDay]')
    check('charge calendar marks days in Nov', days.count() > 0)
    check('history list limited to calendar month', all('11월' in t or '2026년 11월' in t for t in page.locator('#histList .day-head').all_inner_texts()), page.locator('#histList .day-head').all_inner_texts())
    days.first.click(); page.wait_for_selector('#mList.show'); page.screenshot(path=f'{SHOTS}/17_charge_day.png'); page.keyboard.press('Escape'); page.wait_for_timeout(150)
    page.click('#chargeCal [data-action=calMove][data-dir="-1"]'); page.wait_for_timeout(150)
    check('calendar prev month -> October list', '2026년 10월' in page.inner_text('#histCount') and page.locator('#histList .item').count() >= 1, page.inner_text('#histCount'))
    page.click('#histAllBtn'); page.wait_for_timeout(150)
    check('all-period toggle', '전체 기간' in page.inner_text('#histCount'))
    page.click('#histAllBtn'); page.click('#chargeCal [data-action=calToday]'); page.wait_for_timeout(150)

    # ── settings (shared config)
    page.click('[data-page=settings]'); page.wait_for_timeout(200)
    page.click('#gearBtn'); page.wait_for_timeout(200)
    check('gear toggles settings closed -> back to history', page.locator('#page-history.active').count() == 1 and page.locator('#gearBtn.active').count() == 0)
    page.click('#gearBtn'); page.wait_for_timeout(200)
    check('gear reopens settings', page.locator('#page-settings.active').count() == 1 and page.locator('#gearBtn.active').count() == 1)
    page.screenshot(path=f'{SHOTS}/12_settings.png', full_page=True)
    page.fill('[data-cfg=airValidDays]', '45'); page.wait_for_timeout(1300)
    check('config saved to Firestore', store['config'].get('settings', {}).get('airValidDays') == 45, store['config'])
    page.fill('[data-cfg=airValidDays]', '30'); page.wait_for_timeout(1300)

    # ── report popup
    page.click('[data-action=openReport]'); page.wait_for_selector('#mReport.show')
    page.fill('#rMonth', '2026-10'); page.fill('#rApprover', '<b>과장</b>')
    with ctx.expect_page() as pinfo:
        page.click('[data-action=printReport]')
    rp = pinfo.value; rp.wait_for_load_state()
    rhtml = rp.content()
    check('report escapes data', '&lt;img src=x' in rhtml and '<img src=x onerror' not in rhtml and '&lt;b&gt;과장' in rhtml)
    check('report has october rows', rp.locator('tbody tr').count() >= 2, rp.locator('tbody tr').count())
    rp.screenshot(path=f'{SHOTS}/13_report.png', full_page=True); rp.close()

    # ── excel
    if xlsx_js:
        with page.expect_download() as dl:
            page.click('#excelBtn')
        check('excel downloaded', dl.value.suggested_filename.endswith('.xlsx'), dl.value.suggested_filename)

    # ── delete tank (cascade) with typed confirmation
    page.click('nav [data-page=tanks]'); page.locator('#tankList .tank', has_text='SCU-001').click(); page.wait_for_selector('#mDetail.show')
    state['prompt'] = 'scu-001'; nC = sum(1 for v in store['charges'].values() if v['tankId'] == 'SCU-001')
    page.click('#mDetail [data-action=deleteTank]'); page.wait_for_selector('#mDetail:not(.show)', state='attached')
    check('tank + its charges/insps deleted atomically', 'T1' not in store['tanks'] and not any(v['tankId'] == 'SCU-001' for v in store['charges'].values()) and not any(v['tankId'] == 'SCU-001' for v in store['inspections'].values()) and len(commits[-1]['writes']) == nC + 2, len(commits[-1]['writes']))

    # ── offline save blocked
    ctx.set_offline(True); page.wait_for_timeout(200)
    check('offline banner shown', page.locator('#offlineBanner:not(.hidden)').count() == 1)
    page.click('header [data-page=scan]'); page.fill('#manualId', 'MED-01'); page.keyboard.press('Enter')
    page.select_option('#cUsage', '장비점검'); page.fill('#cCharger', 'x'); page.click('#saveChargeBtn'); page.wait_for_timeout(300)
    check('offline save blocked with message', '오프라인' in toast(), toast())
    page.screenshot(path=f'{SHOTS}/14_offline.png')
    ctx.set_offline(False); page.wait_for_timeout(1500)

    # ── back button closes modal (android)
    page.click('nav [data-page=tanks]'); page.locator('#tankList .tank').first.click(); page.wait_for_selector('#mDetail.show')
    page.go_back(); page.wait_for_timeout(300)
    check('browser back closes modal, stays in app', page.locator('#mDetail.show').count() == 0 and page.locator('#login.hidden').count() == 1)

    # ── reload: session kept, cache used
    page.reload(); page.wait_for_timeout(800)
    check('login persisted after reload', page.locator('#login.hidden').count() == 1)
    check('expire popup not repeated in same session', page.locator('#mList.show').count() == 0)

    # ── 403 on sync after reload with fresh context -> logout message
    state['deny403'] = True
    ctx2 = b.new_context(viewport={'width': 390, 'height': 844}, timezone_id='Asia/Seoul', service_workers='block')
    for pat, h in [(r'https://firestore\.googleapis\.com/.*', handle_fs), (r'https://identitytoolkit\.googleapis\.com/.*', handle_idt), (r'https://securetoken\.googleapis\.com/.*', handle_sts)]:
        ctx2.route(re.compile(pat), h)
    ctx2.route(re.compile(r'https://fonts\..*'), lambda r, q: r.fulfill(status=200, body=''))
    p2 = ctx2.new_page(); csp_err = []
    p2.on('console', lambda m: csp_err.append(m.text) if 'Content Security Policy' in m.text else None)
    p2.goto(f'http://127.0.0.1:{PORT}/index.html')
    p2.fill('#loginPw', 'pass1234'); p2.click('#loginBtn'); p2.wait_for_timeout(1000)
    check('no-permission account -> back to login with reason', p2.locator('#login:not(.hidden)').count() == 1 and '권한' in p2.inner_text('#loginErr'), p2.inner_text('#loginErr'))
    state['deny403'] = False
    check('CSP: app runs without CSP violations', not csp_err, csp_err[:3])

    # ── password change
    page.click('[data-page=settings]'); page.click('[data-action=openPw]'); page.wait_for_selector('#mPw.show')
    page.fill('#pwCur', 'pass1234'); page.fill('#pwNew', 'newpass99'); page.fill('#pwNew2', 'newpass99'); page.click('#savePwBtn'); page.wait_for_timeout(400)
    check('password changed', state['pw'] == 'newpass99')

    # desktop screenshot
    page.set_viewport_size({'width': 1280, 'height': 900}); page.click('nav [data-page=dashboard]'); page.wait_for_timeout(200)
    page.screenshot(path=f'{SHOTS}/15_desktop.png')

    check('no XSS alert fired', not alerts, alerts)
    real_err = [e for e in errors if 'favicon' not in e and 'Failed to load resource' not in e]
    check('no JS errors', not real_err, real_err[:5])
    b.close()

fails = [r for r in results if not r[1]]
print(f'\n{len(results) - len(fails)}/{len(results)} passed')
