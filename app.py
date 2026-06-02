#!/usr/bin/env python3
"""
SIEM Enterprise v2.0 — Real-Time Security Monitoring
Monitors: Live processes, network connections, system resources, login attempts
"""

import os, sys, json, threading, queue, time, logging
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
import hashlib, secrets, socket, re, platform
from datetime import datetime, timedelta
from collections import defaultdict, deque
import random, uuid

import psutil
from flask import Flask, render_template, jsonify, request, session, redirect
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# ── LOGGING ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('SIEM')

# ── CONFIG ─────────────────────────────────────────────────────────────────────
IS_WINDOWS = sys.platform == 'win32'
DISK_PATH  = 'C:\\' if IS_WINDOWS else '/'

SUSPICIOUS_PROCS = {
    'mimikatz','netcat','ncat','nc','nmap','masscan','metasploit',
    'msfconsole','sqlmap','hydra','john','hashcat','aircrack',
    'wireshark','tcpdump','ettercap','responder','impacket',
    'bloodhound','crackmapexec','cobaltstrike','empire','powersploit',
}
SUSPICIOUS_PORTS = {4444,5555,6666,7777,8888,9999,1234,31337,4321,
                    1337,12345,54321,6667,6697,1080,3128,8118}
KNOWN_SAFE_PROCS = {
    'python','python3','python.exe','node','node.exe','chrome',
    'firefox','code','explorer','svchost','system','idle',
    'conhost','dwm','winlogon','csrss','smss','wininit',
}

MITRE = {
    'LOGIN_FAILURE':         'TA0006 - Credential Access',
    'BRUTE_FORCE':           'TA0006 - Credential Access',
    'PRIVILEGE_ESCALATION':  'TA0004 - Privilege Escalation',
    'SUSPICIOUS_PROCESS':    'TA0002 - Execution',
    'SUSPICIOUS_CONNECTION': 'TA0011 - Command & Control',
    'PORT_SCAN':             'TA0007 - Discovery',
    'LATERAL_MOVEMENT':      'TA0008 - Lateral Movement',
    'DATA_EXFILTRATION':     'TA0010 - Exfiltration',
    'MALWARE_DETECTED':      'TA0001 - Initial Access',
    'FILE_ACCESS':           'TA0009 - Collection',
    'SQL_INJECTION':         'TA0001 - Initial Access',
    'HIGH_CPU_USAGE':        'TA0040 - Impact',
    'NETWORK_ANOMALY':       'TA0011 - Command & Control',
    'USER_CREATED':          'TA0003 - Persistence',
}

GEO = [
    ('US','New York'),('US','Los Angeles'),('CN','Beijing'),('RU','Moscow'),
    ('DE','Berlin'),('GB','London'),('FR','Paris'),('IN','Mumbai'),
    ('BR','São Paulo'),('AU','Sydney'),('JP','Tokyo'),('KP','Pyongyang'),
    ('IR','Tehran'),('NL','Amsterdam'),('SG','Singapore'),('UA','Kyiv'),
    ('TR','Istanbul'),('VN','Hanoi'),('NG','Lagos'),('MX','Mexico City'),
]

# ── FLASK ──────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = secrets.token_hex(32)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading',
                    logger=False, engineio_logger=False,
                    ping_timeout=60, ping_interval=25)

# ── DATABASE (MongoDB) ─────────────────────────────────────────────────────────
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
MONGODB_DB_NAME = os.environ.get('MONGODB_DB', 'siem_v2')

class DB:
    def __init__(self):
        self._lock = threading.Lock()
        self.client = MongoClient(MONGODB_URI)
        self.db = self.client[MONGODB_DB_NAME]
        self._init()

    def _c(self, name):
        return self.db[name]

    @staticmethod
    def _ts(val=None):
        if val is None:
            return datetime.now()
        if isinstance(val, datetime):
            return val
        if isinstance(val, str):
            try:
                return datetime.fromisoformat(val)
            except ValueError:
                return datetime.now()
        return datetime.now()

    @staticmethod
    def _doc(doc):
        if not doc:
            return doc
        out = {}
        for k, v in doc.items():
            if k == '_id':
                continue
            out[k] = v.isoformat() if isinstance(v, datetime) else v
        if 'id' not in out:
            out['id'] = doc.get('id', str(doc['_id']))
        return out

    @staticmethod
    def _docs(cursor):
        return [DB._doc(d) for d in cursor]

    def _init(self):
        for coll, key in [
            ('users', 'username'),
            ('events', 'eid'),
            ('alerts', 'alert_id'),
            ('incidents', 'incident_id'),
            ('threat_intel', 'indicator'),
            ('rules', 'id'),
        ]:
            self._c(coll).create_index(key, unique=True)
        self._c('events').create_index([('timestamp', -1)])
        self._c('alerts').create_index([('timestamp', -1)])
        self._c('network_snapshot').create_index([('timestamp', -1)])

        pw = hashlib.sha256('admin123'.encode()).hexdigest()
        self._c('users').update_one(
            {'username': 'admin'},
            {'$setOnInsert': {
                'username': 'admin',
                'password_hash': pw,
                'role': 'admin',
                'created_at': datetime.now(),
            }},
            upsert=True,
        )

        for rid, r in enumerate([
            ('Brute Force Detection', '≥5 failed logins in 5 min', 'LOGIN_FAILURE>5', 'high'),
            ('Privilege Escalation', 'Privilege escalation attempt', 'PRIVILEGE_ESCALATION', 'critical'),
            ('Suspicious Process', 'Known malicious process running', 'SUSPICIOUS_PROCESS', 'high'),
            ('Port Scan', 'Port scanning activity', 'PORT_SCAN', 'medium'),
            ('Data Exfiltration', 'Large outbound data transfer', 'DATA_EXFILTRATION', 'critical'),
            ('Suspicious Connection', 'Connection to suspicious port', 'SUSPICIOUS_CONNECTION', 'high'),
            ('High CPU Alert', 'CPU usage above 85%', 'CPU>85', 'medium'),
        ], start=1):
            self._c('rules').update_one(
                {'id': rid},
                {'$setOnInsert': {
                    'id': rid,
                    'name': r[0],
                    'description': r[1],
                    'condition': r[2],
                    'severity': r[3],
                    'enabled': True,
                    'triggered_count': 0,
                    'created_at': datetime.now(),
                }},
                upsert=True,
            )

        now = datetime.now()
        for ioc in [
            ('185.220.101.1', 'IP', 'TOR Exit Node', 95),
            ('45.142.212.100', 'IP', 'Known C2 Server', 92),
            ('141.98.80.135', 'IP', 'Port Scanner', 80),
            ('176.10.104.240', 'IP', 'Known Attacker', 88),
            ('195.54.160.149', 'IP', 'Botnet Node', 85),
            ('malware-c2.evil.com', 'Domain', 'C2 Infrastructure', 95),
            ('d41d8cd98f00b204e9800998ecf8427e', 'MD5', 'Known Malware Hash', 99),
        ]:
            self._c('threat_intel').update_one(
                {'indicator': ioc[0]},
                {'$setOnInsert': {
                    'indicator': ioc[0],
                    'indicator_type': ioc[1],
                    'threat_type': ioc[2],
                    'confidence': ioc[3],
                    'first_seen': now,
                    'last_seen': now,
                    'hit_count': 0,
                }},
                upsert=True,
            )
        log.info(f"MongoDB connected: {MONGODB_URI} / {MONGODB_DB_NAME}")

    def authenticate(self, username, password_hash):
        user = self._c('users').find_one({'username': username, 'password_hash': password_hash})
        return self._doc(user) if user else None

    def save_event(self, e):
        eid = str(uuid.uuid4())[:12]
        mitre = MITRE.get(e.get('event_type', ''), '')
        doc = {
            'eid': eid,
            'timestamp': self._ts(e.get('timestamp')),
            'event_type': e.get('event_type'),
            'severity': e.get('severity', 'info'),
            'source_ip': e.get('source_ip'),
            'dest_ip': e.get('dest_ip'),
            'username': e.get('username'),
            'message': e.get('message', ''),
            'threat_score': e.get('threat_score', 0),
            'source': e.get('source', 'system'),
            'process_name': e.get('process_name'),
            'file_path': e.get('file_path'),
            'mitre_tactic': mitre,
            'geo_country': e.get('geo_country'),
            'geo_city': e.get('geo_city'),
            'pid': e.get('pid'),
            'port': e.get('port'),
            'raw_data': json.dumps({
                k: v for k, v in e.items()
                if isinstance(v, (str, int, float, bool, type(None)))
            }),
        }
        try:
            with self._lock:
                self._c('events').insert_one(doc)
        except DuplicateKeyError:
            log.debug(f"save_event duplicate eid: {eid}")
        except Exception as ex:
            log.debug(f"save_event: {ex}")
        return eid

    def save_alert(self, a):
        aid = 'ALT-' + str(uuid.uuid4())[:8].upper()
        mitre = MITRE.get(a.get('event_type', ''), '')
        doc = {
            'alert_id': aid,
            'timestamp': self._ts(a.get('timestamp')),
            'title': a.get('title', 'Alert'),
            'description': a.get('description', ''),
            'severity': a.get('severity', 'medium'),
            'rule_name': a.get('rule_name', 'AUTO'),
            'source_ip': a.get('source_ip'),
            'status': 'new',
            'mitre_tactic': mitre,
        }
        try:
            with self._lock:
                self._c('alerts').insert_one(doc)
        except DuplicateKeyError:
            log.debug(f"save_alert duplicate: {aid}")
        except Exception as ex:
            log.debug(f"save_alert: {ex}")
        return aid

    def get_events(self, limit=100, severity=None, search=None):
        filt = {}
        if severity and severity != 'all':
            filt['severity'] = severity
        if search:
            rx = {'$regex': re.escape(search), '$options': 'i'}
            filt['$or'] = [
                {'message': rx}, {'source_ip': rx},
                {'username': rx}, {'process_name': rx},
            ]
        cur = self._c('events').find(filt).sort('timestamp', -1).limit(limit)
        return self._docs(cur)

    def get_alerts(self, limit=100, status=None):
        filt = {}
        if status and status != 'all':
            filt['status'] = status
        cur = self._c('alerts').find(filt).sort('timestamp', -1).limit(limit)
        return self._docs(cur)

    def update_alert(self, alert_id, updates):
        parsed = {k: self._ts(v) if k in ('timestamp', 'resolved_at') else v for k, v in updates.items()}
        with self._lock:
            self._c('alerts').update_one({'alert_id': alert_id}, {'$set': parsed})

    def create_incident(self, d):
        iid = f"INC-{datetime.now().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
        now = datetime.now()
        with self._lock:
            self._c('incidents').insert_one({
                'incident_id': iid,
                'title': d['title'],
                'description': d.get('description', ''),
                'severity': d.get('severity', 'medium'),
                'status': 'open',
                'assigned_to': d.get('assigned_to', ''),
                'affected_assets': d.get('affected_assets', ''),
                'created_at': now,
                'updated_at': now,
            })
        return iid

    def get_incidents(self, limit=50):
        cur = self._c('incidents').find().sort('created_at', -1).limit(limit)
        return self._docs(cur)

    def update_incident(self, iid, updates):
        updates['updated_at'] = datetime.now()
        with self._lock:
            self._c('incidents').update_one({'incident_id': iid}, {'$set': updates})

    def get_threat_intel(self, limit=100, search=None):
        filt = {}
        if search:
            rx = {'$regex': re.escape(search), '$options': 'i'}
            filt['$or'] = [{'indicator': rx}, {'threat_type': rx}]
        cur = (self._c('threat_intel').find(filt)
               .sort([('confidence', -1), ('hit_count', -1)]).limit(limit))
        return self._docs(cur)

    def add_ioc(self, ioc):
        now = datetime.now()
        with self._lock:
            self._c('threat_intel').update_one(
                {'indicator': ioc['indicator']},
                {'$set': {
                    'indicator_type': ioc['indicator_type'],
                    'threat_type': ioc['threat_type'],
                    'confidence': ioc['confidence'],
                    'last_seen': now,
                }, '$setOnInsert': {'first_seen': now, 'hit_count': 0}},
                upsert=True,
            )

    def hit_ioc(self, indicator):
        with self._lock:
            self._c('threat_intel').update_one(
                {'indicator': indicator},
                {'$inc': {'hit_count': 1}, '$set': {'last_seen': datetime.now()}},
            )

    def get_known_ioc_ips(self):
        return {
            d['indicator'] for d in self._c('threat_intel').find(
                {'indicator_type': 'IP'}, {'indicator': 1})
        }

    def get_rules(self):
        cur = self._c('rules').find().sort('id', 1)
        return self._docs(cur)

    def toggle_rule(self, rid, enabled):
        with self._lock:
            self._c('rules').update_one({'id': rid}, {'$set': {'enabled': bool(enabled)}})

    def inc_rule(self, rid):
        with self._lock:
            self._c('rules').update_one({'id': rid}, {'$inc': {'triggered_count': 1}})

    def summary(self):
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        events = self._c('events')
        alerts = self._c('alerts')
        return {
            'total_events': events.count_documents({}),
            'events_today': events.count_documents({'timestamp': {'$gte': today_start}}),
            'total_alerts': alerts.count_documents({}),
            'open_alerts': alerts.count_documents({'status': 'new'}),
            'critical_alerts': alerts.count_documents({'severity': 'critical', 'status': 'new'}),
            'open_incidents': self._c('incidents').count_documents({'status': 'open'}),
            'ioc_count': self._c('threat_intel').count_documents({}),
        }

    def save_net_snapshot(self, data):
        with self._lock:
            coll = self._c('network_snapshot')
            coll.insert_one({
                'timestamp': datetime.now(),
                'connections_count': data['connections'],
                'bytes_sent': data['bytes_sent'],
                'bytes_recv': data['bytes_recv'],
                'packets_sent': data['packets_sent'],
                'packets_recv': data['packets_recv'],
            })
            excess = coll.count_documents({}) - 500
            if excess > 0:
                oldest = list(coll.find({}, {'_id': 1}).sort('timestamp', 1).limit(excess))
                coll.delete_many({'_id': {'$in': [d['_id'] for d in oldest]}})

    def get_net_history(self, limit=60):
        cur = self._c('network_snapshot').find().sort('timestamp', -1).limit(limit)
        return self._docs(cur)

    def events_timeline(self, hours=24):
        since = datetime.now() - timedelta(hours=hours)
        pipeline = [
            {'$match': {'timestamp': {'$gte': since}}},
            {'$group': {'_id': {'$hour': '$timestamp'}, 'cnt': {'$sum': 1}}},
        ]
        rows = list(self._c('events').aggregate(pipeline))
        counts = [0] * 24
        for r in rows:
            counts[int(r['_id'])] = r['cnt']
        labels = [f"{str(i).zfill(2)}:00" for i in range(24)]
        return {'labels': labels, 'counts': counts}

    def events_severity_distribution(self, hours=24):
        since = datetime.now() - timedelta(hours=hours)
        pipeline = [
            {'$match': {'timestamp': {'$gte': since}}},
            {'$group': {'_id': '$severity', 'cnt': {'$sum': 1}}},
        ]
        return {r['_id']: r['cnt'] for r in self._c('events').aggregate(pipeline) if r['_id']}

    def events_by_type(self, hours=24, limit=10):
        since = datetime.now() - timedelta(hours=hours)
        pipeline = [
            {'$match': {'timestamp': {'$gte': since}}},
            {'$group': {'_id': '$event_type', 'cnt': {'$sum': 1}}},
            {'$sort': {'cnt': -1}},
            {'$limit': limit},
        ]
        return [{'event_type': r['_id'], 'cnt': r['cnt']} for r in self._c('events').aggregate(pipeline)]

    def events_geo(self, hours=24, limit=30):
        since = datetime.now() - timedelta(hours=hours)
        pipeline = [
            {'$match': {
                'timestamp': {'$gte': since},
                'geo_country': {'$ne': None},
            }},
            {'$group': {
                '_id': {'geo_country': '$geo_country', 'geo_city': '$geo_city'},
                'cnt': {'$sum': 1},
            }},
            {'$sort': {'cnt': -1}},
            {'$limit': limit},
        ]
        return [{
            'geo_country': r['_id']['geo_country'],
            'geo_city': r['_id']['geo_city'],
            'cnt': r['cnt'],
        } for r in self._c('events').aggregate(pipeline)]

    def top_attackers(self, hours=24, limit=15):
        since = datetime.now() - timedelta(hours=hours)
        pipeline = [
            {'$match': {
                'timestamp': {'$gte': since},
                'source_ip': {'$ne': None},
                'severity': {'$in': ['critical', 'high', 'medium']},
            }},
            {'$group': {
                '_id': '$source_ip',
                'attacks': {'$sum': 1},
                'max_score': {'$max': '$threat_score'},
                'geo_country': {'$first': '$geo_country'},
                'geo_city': {'$first': '$geo_city'},
            }},
            {'$sort': {'attacks': -1}},
            {'$limit': limit},
        ]
        return [{
            'source_ip': r['_id'],
            'attacks': r['attacks'],
            'max_score': r['max_score'],
            'geo_country': r.get('geo_country'),
            'geo_city': r.get('geo_city'),
        } for r in self._c('events').aggregate(pipeline)]

    def mitre_coverage(self, hours=24):
        since = datetime.now() - timedelta(hours=hours)
        pipeline = [
            {'$match': {
                'timestamp': {'$gte': since},
                'mitre_tactic': {'$nin': [None, '']},
            }},
            {'$group': {'_id': '$mitre_tactic', 'cnt': {'$sum': 1}}},
            {'$sort': {'cnt': -1}},
        ]
        return [{'mitre_tactic': r['_id'], 'cnt': r['cnt']} for r in self._c('events').aggregate(pipeline)]

    def report_summary(self):
        since_7d = datetime.now() - timedelta(days=7)
        since_30d = datetime.now() - timedelta(days=30)
        events = self._c('events')

        top_types = list(events.aggregate([
            {'$match': {'timestamp': {'$gte': since_7d}}},
            {'$group': {'_id': '$event_type', 'cnt': {'$sum': 1}}},
            {'$sort': {'cnt': -1}}, {'$limit': 10},
        ]))
        top_ips = list(events.aggregate([
            {'$match': {'timestamp': {'$gte': since_7d}, 'source_ip': {'$ne': None}}},
            {'$group': {'_id': '$source_ip', 'cnt': {'$sum': 1}}},
            {'$sort': {'cnt': -1}}, {'$limit': 10},
        ]))
        daily = list(events.aggregate([
            {'$match': {'timestamp': {'$gte': since_30d}}},
            {'$group': {
                '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}},
                'cnt': {'$sum': 1},
            }},
            {'$sort': {'_id': 1}},
        ]))
        return {
            'top_event_types': [{'event_type': r['_id'], 'cnt': r['cnt']} for r in top_types],
            'top_source_ips': [{'source_ip': r['_id'], 'cnt': r['cnt']} for r in top_ips],
            'daily_events': [{'day': r['_id'], 'cnt': r['cnt']} for r in daily],
        }

db = DB()

# ── REAL-TIME MONITORS ─────────────────────────────────────────────────────────

class ProcessMonitor:
    """Continuously scans running processes for threats"""
    def __init__(self, event_q):
        self.q = event_q
        self.seen_pids = {}          # pid → first_seen time
        self.alerted_pids = set()    # already alerted
        self.known_iocs = set()

    def scan(self):
        self.known_iocs = db.get_known_ioc_ips()
        now = datetime.now()
        current_pids = set()

        for proc in psutil.process_iter(['pid','name','exe','cmdline','username',
                                          'cpu_percent','memory_percent','status',
                                          'create_time','connections']):
            try:
                pid  = proc.info['pid']
                name = (proc.info['name'] or '').lower()
                cmd  = ' '.join(proc.info['cmdline'] or []).lower()
                exe  = (proc.info['exe'] or '').lower()
                user = proc.info['username'] or 'SYSTEM'
                cpu  = proc.info['cpu_percent'] or 0
                mem  = proc.info['memory_percent'] or 0
                current_pids.add(pid)

                # Track new processes
                if pid not in self.seen_pids:
                    self.seen_pids[pid] = now

                if pid in self.alerted_pids:
                    continue

                # ── Check: known suspicious name ──────────────────────
                for s in SUSPICIOUS_PROCS:
                    if s in name or s in cmd:
                        self._emit('SUSPICIOUS_PROCESS', 'high', 75,
                            f"Suspicious process detected: {name} (PID:{pid}) by {user}",
                            process_name=name, pid=pid, username=user,
                            source='Process Monitor')
                        self.alerted_pids.add(pid)
                        break

                # ── Check: crypto miners (high CPU + unknown process) ──
                if cpu > 70 and name not in KNOWN_SAFE_PROCS and pid not in self.alerted_pids:
                    self._emit('SUSPICIOUS_PROCESS', 'high', 70,
                        f"Possible cryptominer: {name} (PID:{pid}) consuming {cpu:.1f}% CPU",
                        process_name=name, pid=pid, username=user,
                        source='Process Monitor')
                    self.alerted_pids.add(pid)

                # ── Check: PowerShell with encoded commands ────────────
                if ('powershell' in name or 'pwsh' in name) and ('-enc' in cmd or '-encodedcommand' in cmd or 'bypass' in cmd):
                    self._emit('SUSPICIOUS_PROCESS', 'critical', 90,
                        f"PowerShell encoded command detected (PID:{pid}) — possible obfuscation",
                        process_name=name, pid=pid, username=user,
                        source='Process Monitor')
                    self.alerted_pids.add(pid)

                # ── Check: process network connections to bad ports ────
                try:
                    for conn in proc.connections(kind='inet'):
                        if conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
                            if pid not in self.alerted_pids:
                                self._emit('SUSPICIOUS_CONNECTION', 'high', 80,
                                    f"{name} (PID:{pid}) connected to suspicious port {conn.raddr.port} at {conn.raddr.ip}",
                                    process_name=name, pid=pid,
                                    source_ip=conn.raddr.ip, port=conn.raddr.port,
                                    source='Process Monitor')
                                self.alerted_pids.add(pid)
                        # Check if connecting to known-bad IP
                        if conn.raddr and conn.raddr.ip in self.known_iocs:
                            if pid not in self.alerted_pids:
                                self._emit('MALWARE_DETECTED', 'critical', 95,
                                    f"Process {name} (PID:{pid}) communicating with known C2: {conn.raddr.ip}",
                                    process_name=name, pid=pid,
                                    source_ip=conn.raddr.ip,
                                    source='Threat Intel Match')
                                db.hit_ioc(conn.raddr.ip)
                                self.alerted_pids.add(pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                log.debug(f"proc scan: {e}")

        # Clean up dead PIDs
        dead = set(self.seen_pids) - current_pids
        for p in dead:
            self.seen_pids.pop(p, None)
            self.alerted_pids.discard(p)

    def _emit(self, etype, sev, score, msg, **kwargs):
        geo = random.choice(GEO)
        evt = {
            'timestamp': datetime.now().isoformat(),
            'event_type': etype,
            'severity': sev,
            'threat_score': score,
            'message': msg,
            'geo_country': geo[0],
            'geo_city': geo[1],
            **kwargs
        }
        self.q.put(evt)
        log.warning(f"[PROC] {msg}")


class NetworkMonitor:
    """Monitors network connections in real time"""
    def __init__(self, event_q):
        self.q = event_q
        self.known_conns = {}        # key → first_seen
        self.port_scan_tracker = defaultdict(list)  # src_ip → [timestamps]
        self.brute_force_tracker = defaultdict(list) # src_ip → [timestamps]
        self.prev_net = None
        self.known_iocs = set()
        self._get_prev_net()

    def _get_prev_net(self):
        try:
            self.prev_net = psutil.net_io_counters()
        except Exception:
            self.prev_net = None

    def scan(self):
        self.known_iocs = db.get_known_ioc_ips()
        now = datetime.now()
        conn_count = 0

        try:
            conns = psutil.net_connections(kind='inet')
        except (psutil.AccessDenied, Exception):
            conns = []

        for conn in conns:
            try:
                if not (conn.status == 'ESTABLISHED' and conn.raddr):
                    continue
                conn_count += 1
                rip   = conn.raddr.ip
                rport = conn.raddr.port
                key   = f"{rip}:{rport}"

                # Skip localhost
                if rip.startswith('127.') or rip == '::1':
                    continue

                # New connection seen
                if key not in self.known_conns:
                    self.known_conns[key] = now

                    # Known IOC IP
                    if rip in self.known_iocs:
                        self._emit('SUSPICIOUS_CONNECTION', 'critical', 95,
                            f"Connection to known malicious IP: {rip}:{rport}",
                            source_ip=rip, port=rport, source='Network Monitor')
                        db.hit_ioc(rip)

                    # Suspicious port
                    elif rport in SUSPICIOUS_PORTS:
                        self._emit('SUSPICIOUS_CONNECTION', 'high', 78,
                            f"Connection to suspicious port {rport} at {rip}",
                            source_ip=rip, port=rport, source='Network Monitor')

            except Exception:
                continue

        # Clean old connections (>30 min)
        cutoff = now - timedelta(minutes=30)
        self.known_conns = {k:v for k,v in self.known_conns.items() if v > cutoff}

        # Capture network I/O rates
        try:
            cur = psutil.net_io_counters()
            net_data = {
                'connections': conn_count,
                'bytes_sent':    cur.bytes_sent,
                'bytes_recv':    cur.bytes_recv,
                'packets_sent':  cur.packets_sent,
                'packets_recv':  cur.packets_recv,
            }
            if self.prev_net:
                elapsed = 5
                net_data['in_rate']  = max(0, (cur.bytes_recv - self.prev_net.bytes_recv) / elapsed)
                net_data['out_rate'] = max(0, (cur.bytes_sent - self.prev_net.bytes_sent) / elapsed)
                net_data['pps_in']   = max(0, (cur.packets_recv - self.prev_net.packets_recv) / elapsed)
                net_data['pps_out']  = max(0, (cur.packets_sent - self.prev_net.packets_sent) / elapsed)

                # High traffic anomaly
                if net_data['out_rate'] > 50_000_000:  # >50 MB/s out
                    self._emit('DATA_EXFILTRATION', 'critical', 88,
                        f"Abnormally high outbound traffic: {net_data['out_rate']/1024/1024:.1f} MB/s",
                        source='Network Monitor')
            else:
                net_data.update({'in_rate':0,'out_rate':0,'pps_in':0,'pps_out':0})
            self.prev_net = cur
            db.save_net_snapshot(net_data)
            return net_data
        except Exception:
            return {'connections':conn_count,'bytes_sent':0,'bytes_recv':0,
                    'packets_sent':0,'packets_recv':0,'in_rate':0,'out_rate':0,'pps_in':0,'pps_out':0}

    def _emit(self, etype, sev, score, msg, **kwargs):
        geo = random.choice(GEO)
        evt = {'timestamp': datetime.now().isoformat(), 'event_type': etype,
               'severity': sev, 'threat_score': score, 'message': msg,
               'geo_country': geo[0], 'geo_city': geo[1], **kwargs}
        self.q.put(evt)
        log.warning(f"[NET] {msg}")


class SystemMonitor:
    """Polls real system metrics every second"""
    def __init__(self, event_q):
        self.q = event_q
        self.data = {}
        self._cpu_high_since = None
        self._mem_high_since = None
        self._disk_high_since = None
        self._alert_cooldown = {}   # event_type → last_alerted time

    def poll(self):
        try:
            cpu  = psutil.cpu_percent(interval=0)
            mem  = psutil.virtual_memory()
            disk = self._safe_disk()
            now  = datetime.now()

            self.data = {
                'cpu':          round(cpu, 1),
                'memory':       round(mem.percent, 1),
                'memory_used':  round(mem.used  / 1024**3, 2),
                'memory_total': round(mem.total / 1024**3, 2),
                'disk':         disk['percent'],
                'disk_used':    disk['used'],
                'disk_total':   disk['total'],
                'hostname':     socket.gethostname(),
                'platform':     platform.system(),
                'timestamp':    now.isoformat(),
                'cpu_count':    psutil.cpu_count(),
                'boot_time':    datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            }

            # ── Threshold alerts (with cooldown 5 min) ────────────────
            if cpu > 85 and self._can_alert('HIGH_CPU', 300):
                self.q.put({'event_type':'HIGH_CPU_USAGE','severity':'medium',
                    'threat_score':40, 'source':'System Monitor',
                    'message':f"CPU usage critical: {cpu:.1f}% on {socket.gethostname()}",
                    'timestamp': now.isoformat()})

            if mem.percent > 88 and self._can_alert('HIGH_MEM', 300):
                self.q.put({'event_type':'HIGH_MEMORY_USAGE','severity':'medium',
                    'threat_score':35, 'source':'System Monitor',
                    'message':f"Memory pressure: {mem.percent:.1f}% used ({mem.used//1024**3}GB/{mem.total//1024**3}GB)",
                    'timestamp': now.isoformat()})

            if disk['percent'] > 90 and self._can_alert('HIGH_DISK', 600):
                self.q.put({'event_type':'FILE_ACCESS','severity':'high',
                    'threat_score':55, 'source':'System Monitor',
                    'message':f"Disk nearly full: {disk['percent']}% used on {DISK_PATH}",
                    'timestamp': now.isoformat()})

        except Exception as e:
            log.debug(f"system poll: {e}")

        return self.data

    def _safe_disk(self):
        try:
            d = psutil.disk_usage(DISK_PATH)
            return {'percent': round(d.percent,1),
                    'used':    round(d.used /1024**3,1),
                    'total':   round(d.total/1024**3,1)}
        except Exception:
            return {'percent':0,'used':0,'total':0}

    def _can_alert(self, key, cooldown_secs):
        now = time.time()
        last = self._alert_cooldown.get(key, 0)
        if now - last > cooldown_secs:
            self._alert_cooldown[key] = now
            return True
        return False

    def top_processes(self, n=10):
        procs = []
        for p in psutil.process_iter(['pid','name','cpu_percent','memory_percent','status','username']):
            try:
                procs.append({'pid':p.info['pid'], 'name':p.info['name'],
                              'cpu':round(p.info['cpu_percent'],1),
                              'mem':round(p.info['memory_percent'],1),
                              'status':p.info['status'],
                              'user':p.info['username'] or ''})
            except Exception:
                pass
        return sorted(procs, key=lambda x: x['cpu'], reverse=True)[:n]

    def live_connections(self, limit=20):
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.raddr and c.status == 'ESTABLISHED':
                    conns.append({
                        'local':  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else '—',
                        'remote': f"{c.raddr.ip}:{c.raddr.port}",
                        'status': c.status,
                        'pid':    c.pid or 0,
                    })
        except Exception:
            pass
        return conns[:limit]


class BruteForceDetector:
    """Tracks repeated failed logins and fires alerts"""
    def __init__(self, event_q):
        self.q = event_q
        self.fails = defaultdict(deque)  # ip → deque of timestamps
        self.alerted = {}                # ip → last_alert_time
        self.WINDOW = 300   # 5 min
        self.THRESHOLD = 5

    def record_fail(self, ip, username='unknown'):
        now = time.time()
        dq  = self.fails[ip]
        dq.append(now)
        # Trim old
        while dq and now - dq[0] > self.WINDOW:
            dq.popleft()
        # Check threshold
        if len(dq) >= self.THRESHOLD:
            last = self.alerted.get(ip, 0)
            if now - last > self.WINDOW:
                self.alerted[ip] = now
                geo = random.choice(GEO)
                self.q.put({
                    'event_type': 'BRUTE_FORCE',
                    'severity':   'high',
                    'threat_score': 85,
                    'source_ip':  ip,
                    'username':   username,
                    'message':    f"Brute force detected: {len(dq)} failed logins from {ip} targeting '{username}' in 5 min",
                    'source':     'Auth Monitor',
                    'geo_country': geo[0],
                    'geo_city':    geo[1],
                    'timestamp':   datetime.now().isoformat(),
                })
                db.inc_rule(1)
                log.warning(f"[BRUTE] {ip} → {len(dq)} fails")


# ── SIEM ENGINE ─────────────────────────────────────────────────────────────────
class SiemEngine:
    def __init__(self):
        self.q = queue.Queue(maxsize=2000)
        self.recent_events = deque(maxlen=500)
        self.running = True
        self.total = 0
        self.eps_window = deque(maxlen=100)  # recent event timestamps

        self.proc_mon   = ProcessMonitor(self.q)
        self.net_mon    = NetworkMonitor(self.q)
        self.sys_mon    = SystemMonitor(self.q)
        self.brute      = BruteForceDetector(self.q)

        # Live metrics (pushed every second)
        self.live = {
            'cpu':0,'memory':0,'disk':0,
            'net_in':0,'net_out':0,'connections':0,
            'eps':0.0,'total':0,
        }
        self._start()
        log.info("✅ SIEM Real-Time Engine started")

    def _start(self):
        threading.Thread(target=self._process_loop,  daemon=True, name='EventProcessor').start()
        threading.Thread(target=self._system_loop,   daemon=True, name='SystemPoller').start()
        threading.Thread(target=self._process_scan,  daemon=True, name='ProcessScanner').start()
        threading.Thread(target=self._network_scan,  daemon=True, name='NetworkScanner').start()
        threading.Thread(target=self._broadcast_1s,  daemon=True, name='Broadcaster').start()
        log.info("✅ All monitoring threads started")

    def _process_loop(self):
        """Dequeue events, save, alert, and broadcast"""
        while self.running:
            try:
                evt = self.q.get(timeout=1)
                eid = db.save_event(evt)
                evt['eid'] = eid
                self.recent_events.appendleft(evt)
                self.eps_window.append(time.time())
                self.total += 1

                # Auto-alert for threat_score ≥ 65
                if evt.get('threat_score', 0) >= 65:
                    aid = db.save_alert({
                        'timestamp':   evt['timestamp'],
                        'title':       f"🚨 {evt['event_type'].replace('_',' ').title()}",
                        'description': evt['message'],
                        'severity':    evt['severity'],
                        'rule_name':   'AUTO_DETECT',
                        'source_ip':   evt.get('source_ip'),
                        'event_type':  evt.get('event_type'),
                    })
                    alert_payload = {**evt, 'alert_id': aid}
                    socketio.emit('new_alert', alert_payload)

                if evt.get('source_ip'):
                    db.hit_ioc(evt['source_ip'])

                socketio.emit('new_event', evt)

            except queue.Empty:
                pass
            except Exception as e:
                log.error(f"process_loop: {e}")

    def _system_loop(self):
        """Poll system metrics every 1 second and push via WebSocket"""
        while self.running:
            try:
                data = self.sys_mon.poll()
                self.live.update({
                    'cpu':    data.get('cpu', 0),
                    'memory': data.get('memory', 0),
                    'disk':   data.get('disk', 0),
                })
                socketio.emit('system_tick', data)
                time.sleep(1)
            except Exception as e:
                log.debug(f"system_loop: {e}")
                time.sleep(1)

    def _process_scan(self):
        """Scan processes every 8 seconds"""
        time.sleep(3)
        while self.running:
            try:
                self.proc_mon.scan()
            except Exception as e:
                log.debug(f"process_scan: {e}")
            time.sleep(8)

    def _network_scan(self):
        """Scan network every 5 seconds"""
        time.sleep(5)
        while self.running:
            try:
                net_data = self.net_mon.scan()
                self.live.update({
                    'net_in':      net_data.get('in_rate', 0),
                    'net_out':     net_data.get('out_rate', 0),
                    'connections': net_data.get('connections', 0),
                })
                socketio.emit('network_tick', net_data)
            except Exception as e:
                log.debug(f"network_scan: {e}")
            time.sleep(5)

    def _broadcast_1s(self):
        """Push aggregated stats every 2 seconds"""
        while self.running:
            try:
                now = time.time()
                recent = [t for t in self.eps_window if now - t < 10]
                eps = round(len(recent) / 10, 2)
                self.live['eps']   = eps
                self.live['total'] = self.total

                stats = db.summary()
                stats['eps']   = eps
                stats['total'] = self.total
                stats['live']  = self.live.copy()
                socketio.emit('stats_update', stats)
            except Exception as e:
                log.debug(f"broadcast: {e}")
            time.sleep(2)

    def inject(self, evt):
        self.q.put({**evt, 'timestamp': datetime.now().isoformat(), 'source': 'Manual Injection'})


siem = SiemEngine()


# ── AUTH ────────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        ct = request.content_type or ''
        data = request.get_json(silent=True) if 'json' in ct else request.form
        if not data:
            data = {}
        username = data.get('username','')
        password = data.get('password','')
        if not username or not password:
            return render_template('login.html', error='Username and password required')
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        user = db.authenticate(username, pw_hash)
        if user:
            session['user'] = username
            session['role'] = user['role']
            if 'json' in ct:
                return jsonify({'status':'ok','username':username,'role':user['role']})
            return redirect('/')
        # Track brute force on login endpoint
        ip = request.remote_addr or '127.0.0.1'
        siem.brute.record_fail(ip, username)
        if 'json' in ct:
            return jsonify({'status':'error','message':'Invalid credentials'}), 401
        return render_template('login.html', error='Invalid credentials — default: admin / admin123')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ── PAGES ───────────────────────────────────────────────────────────────────────
@app.route('/')
def dashboard(): return render_template('dashboard.html', user=session.get('user','Guest'))

@app.route('/threats')
def threats(): return render_template('threats.html', user=session.get('user','Guest'))

@app.route('/incidents')
def incidents(): return render_template('incidents.html', user=session.get('user','Guest'))

@app.route('/hunting')
def hunting(): return render_template('hunting.html', user=session.get('user','Guest'))

@app.route('/compliance')
def compliance(): return render_template('compliance.html', user=session.get('user','Guest'))

@app.route('/reports')
def reports(): return render_template('reports.html', user=session.get('user','Guest'))

@app.route('/settings')
def settings(): return render_template('settings.html', user=session.get('user','Guest'))


# ── API ─────────────────────────────────────────────────────────────────────────
@app.route('/api/stats')
def api_stats():
    stats = db.summary()
    stats['eps']   = siem.live['eps']
    stats['total'] = siem.total
    stats['live']  = siem.live.copy()
    return jsonify(stats)

@app.route('/api/events')
def api_events():
    return jsonify(db.get_events(
        limit    = request.args.get('limit', 100, int),
        severity = request.args.get('severity'),
        search   = request.args.get('search'),
    ))

@app.route('/api/events/timeline')
def api_timeline():
    return jsonify(db.events_timeline())

@app.route('/api/events/severity')
def api_severity():
    return jsonify(db.events_severity_distribution())

@app.route('/api/events/types')
def api_types():
    return jsonify(db.events_by_type())

@app.route('/api/events/geo')
def api_geo():
    return jsonify(db.events_geo())

@app.route('/api/events/inject', methods=['POST'])
def api_inject():
    d = request.json or {}
    score_map = {'critical':92,'high':75,'medium':50,'low':25,'info':5}
    sev = d.get('severity','medium')
    siem.inject({
        'event_type':   d.get('event_type','TEST'),
        'severity':     sev,
        'source_ip':    d.get('source_ip','127.0.0.1'),
        'username':     d.get('username','test'),
        'message':      d.get('message','Manual test event'),
        'threat_score': d.get('threat_score', score_map.get(sev,50)),
        'geo_country':  random.choice(GEO)[0],
        'geo_city':     random.choice(GEO)[1],
    })
    return jsonify({'status':'ok'})

@app.route('/api/alerts')
def api_alerts():
    return jsonify(db.get_alerts(
        limit  = request.args.get('limit', 100, int),
        status = request.args.get('status'),
    ))

@app.route('/api/alerts/<aid>/resolve', methods=['POST'])
def api_resolve(aid):
    db.update_alert(aid, {'status':'resolved',
        'assigned_to': (request.json or {}).get('assigned_to', session.get('user','analyst')),
        'resolved_at': datetime.now().isoformat()})
    return jsonify({'status':'ok'})

@app.route('/api/alerts/<aid>/acknowledge', methods=['POST'])
def api_ack(aid):
    db.update_alert(aid, {'status':'acknowledged',
        'assigned_to': (request.json or {}).get('assigned_to', session.get('user','analyst'))})
    return jsonify({'status':'ok'})

@app.route('/api/incidents')
def api_incidents(): return jsonify(db.get_incidents())

@app.route('/api/incidents/create', methods=['POST'])
def api_create_inc():
    d = request.json or {}
    iid = db.create_incident(d)
    return jsonify({'status':'ok','incident_id':iid})

@app.route('/api/incidents/<iid>', methods=['PUT'])
def api_update_inc(iid):
    d = request.json or {}
    updates = {k:v for k,v in d.items() if k in ['status','assigned_to','notes','severity']}
    if updates: db.update_incident(iid, updates)
    return jsonify({'status':'ok'})

@app.route('/api/threat-intel')
def api_iocs(): return jsonify(db.get_threat_intel(100, request.args.get('search')))

@app.route('/api/threat-intel/add', methods=['POST'])
def api_add_ioc():
    db.add_ioc(request.json or {})
    return jsonify({'status':'ok'})

@app.route('/api/hunting/search')
def api_hunt():
    q = request.args.get('q','')
    if not q: return jsonify({'events':[],'iocs':[]})
    return jsonify({'events': db.get_events(50, search=q), 'iocs': db.get_threat_intel(20, q)})

@app.route('/api/hunting/top-attackers')
def api_attackers():
    return jsonify(db.top_attackers())

@app.route('/api/hunting/mitre')
def api_mitre():
    return jsonify(db.mitre_coverage())

@app.route('/api/system')
def api_system():
    return jsonify({
        'metrics':     siem.sys_mon.data,
        'live':        siem.live,
        'processes':   siem.sys_mon.top_processes(12),
        'connections': siem.sys_mon.live_connections(20),
        'net_history': db.get_net_history(60),
    })

@app.route('/api/network/history')
def api_net_history():
    return jsonify(db.get_net_history(60))

@app.route('/api/compliance')
def api_compliance():
    s = db.summary()
    penalty = s['critical_alerts'] * 2
    def sc(base): return max(0, min(100, base - penalty))
    return jsonify({'frameworks':[
        {'name':'PCI DSS','score':sc(88),'controls':[
            {'name':'Log Monitoring','status':'compliant','score':95},
            {'name':'Access Control','status':'partial','score':78},
            {'name':'Incident Response','status':'compliant','score':90},
            {'name':'Vulnerability Mgmt','status':'partial','score':72},
        ]},
        {'name':'SOC 2 Type II','score':sc(83),'controls':[
            {'name':'Security Monitoring','status':'compliant','score':92},
            {'name':'Availability','status':'compliant','score':88},
            {'name':'Confidentiality','status':'partial','score':76},
            {'name':'Processing Integrity','status':'compliant','score':85},
        ]},
        {'name':'ISO 27001','score':sc(79),'controls':[
            {'name':'Asset Management','status':'compliant','score':88},
            {'name':'Access Management','status':'partial','score':74},
            {'name':'Cryptography','status':'compliant','score':91},
            {'name':'Physical Security','status':'compliant','score':95},
        ]},
        {'name':'NIST CSF','score':sc(85),'controls':[
            {'name':'Identify','status':'compliant','score':90},
            {'name':'Protect','status':'compliant','score':85},
            {'name':'Detect','status':'compliant','score':95},
            {'name':'Respond','status':'partial','score':78},
            {'name':'Recover','status':'partial','score':70},
        ]},
    ]})

@app.route('/api/rules')
def api_rules(): return jsonify(db.get_rules())

@app.route('/api/rules/<int:rid>/toggle', methods=['POST'])
def api_toggle(rid):
    db.toggle_rule(rid, (request.json or {}).get('enabled', True))
    return jsonify({'status':'ok'})

@app.route('/api/reports/summary')
def api_report():
    report = db.report_summary()
    return jsonify({
        'summary': db.summary(),
        'severity_distribution': db.events_severity_distribution(hours=24 * 7),
        'top_event_types': report['top_event_types'],
        'top_source_ips':  report['top_source_ips'],
        'daily_events':    report['daily_events'],
        'generated_at':    datetime.now().isoformat(),
    })


# ── WEBSOCKET ───────────────────────────────────────────────────────────────────
@socketio.on('connect')
def ws_connect():
    log.info(f"WS connected: {request.sid}")
    emit('connected', {'ts': datetime.now().isoformat()})
    emit('init_data', {
        'stats':         db.summary(),
        'recent_events': list(siem.recent_events)[:20],
        'recent_alerts': db.get_alerts(10),
        'system':        siem.sys_mon.data,
        'live':          siem.live,
    })

@socketio.on('disconnect')
def ws_disconnect():
    log.info(f"WS disconnected: {request.sid}")


# ── MAIN ────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════╗
║       SIEM Enterprise v2.0 — Real-Time Security Monitor      ║
║                                                              ║
║  🔍 Monitoring: Processes · Network · System · Brute Force   ║
║  🌐 Dashboard:  http://localhost:5000                        ║
║  👤 Username:   admin   🔑 Password: admin123                ║
╚══════════════════════════════════════════════════════════════╝
""")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)
