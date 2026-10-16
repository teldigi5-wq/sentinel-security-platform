"""Sensor coverage guarantees: authentication, truthful stale states and no synthetic alerts."""
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sentinel.app import sensor_state
from sentinel.models import SensorStatus, AuditRecord
from test_api import client_for, auth, OP, KEY, AUDIT, post_event, payload


def beat(client, *, body=None, nonce=None, signature=None, sensor="lab-one", timestamp=None):
    raw = body if body is not None else b'{"asset_id":"workstation-1"}'
    nonce = nonce or secrets.token_hex(16)
    stamp = timestamp or str(int(time.time()))
    signature = signature or hmac.new(KEY.encode(), f"{sensor}\n{stamp}\n{nonce}\n{hashlib.sha256(raw).hexdigest()}".encode(), hashlib.sha256).hexdigest()
    return client.post("/api/v1/sensors/heartbeat", content=raw, headers={
        "X-Sentinel-Sensor":sensor,"X-Sentinel-Timestamp":stamp,
        "X-Sentinel-Nonce":nonce,"X-Sentinel-Signature":signature})


def test_never_seen_and_authentication(tmp_path):
    client, _ = client_for(tmp_path)
    assert client.get('/api/v1/sensors').status_code == 401
    assert client.get('/api/v1/sensors', headers={'Authorization':'Bearer invalid'}).status_code == 401
    result = client.get('/api/v1/sensors', headers=auth())
    assert result.status_code == 200
    assert result.headers['cache-control'] == 'no-store'
    assert result.json()['sensors'] == [{
        'sensor_id':'lab-one','asset_id':None,'expected_asset_id':None,
        'binding_mode':'first_contact','status':'never_seen',
        'last_seen_at':None,'last_event_at':None,'heartbeat_count':0,'event_count':0}]
    assert result.json()['stale_after_seconds'] == 180


def test_valid_heartbeat_is_audited_and_does_not_create_security_events(tmp_path):
    client, cfg = client_for(tmp_path)
    assert beat(client).status_code == 202
    status = client.get('/api/v1/sensors', headers=auth()).json()['sensors'][0]
    assert status['status'] == 'healthy'
    assert status['last_seen_at'] is not None and status['last_event_at'] is None
    assert status['heartbeat_count'] == 1 and status['event_count'] == 0
    overview=client.get('/api/v1/overview',headers=auth()).json()
    assert overview['events'] == 0 and overview['alerts'] == 0
    assert client.get('/api/v1/audit/integrity',headers=auth()).json()['valid']
    engine=create_engine(cfg.database_url)
    with Session(engine) as session:
        assert session.scalar(select(AuditRecord.action)) == 'sensor.heartbeat'
    engine.dispose()


def test_invalid_signature_expired_nonce_replay_and_extra_fields_fail_closed(tmp_path):
    client, cfg = client_for(tmp_path)
    assert beat(client,signature='0'*64).status_code == 401
    assert beat(client,timestamp=str(int(time.time())-500)).status_code == 401
    assert beat(client,body=b'{"asset_id":"workstation-1","command":"execute"}').status_code == 422
    nonce=secrets.token_hex(16)
    assert beat(client, nonce=nonce).status_code == 202
    assert beat(client, nonce=nonce).status_code == 409
    assert post_event(client, nonce=nonce).status_code == 409
    assert beat(client, body=b'bad').status_code == 422
    state=client.get('/api/v1/sensors',headers=auth()).json()['sensors'][0]
    assert state['heartbeat_count'] == 1
    assert client.get('/api/v1/audit/integrity',headers=auth()).json()['valid']


def test_stale_coverage_and_return_to_healthy_after_new_event(tmp_path):
    client, cfg = client_for(tmp_path)
    assert beat(client).status_code == 202
    engine=create_engine(cfg.database_url)
    with Session(engine) as session:
        row=session.get(SensorStatus,'lab-one')
        row.last_seen_at=datetime.now(timezone.utc)-timedelta(minutes=4)
        session.commit()
    status=client.get('/api/v1/sensors',headers=auth()).json()['sensors'][0]
    assert status['status']=='stale'
    assert post_event(client).status_code==202
    status=client.get('/api/v1/sensors',headers=auth()).json()['sensors'][0]
    assert status['status']=='healthy' and status['event_count']==1 and status['heartbeat_count']==1
    assert status['last_event_at'] is not None
    engine.dispose()


def test_server_clock_skew_does_not_show_false_green():
    now=datetime.now(timezone.utc)
    assert sensor_state(None,now)=='never_seen'
    assert sensor_state(now-timedelta(seconds=181),now)=='stale'
    assert sensor_state(now-timedelta(seconds=180),now)=='healthy'
    assert sensor_state(now+timedelta(seconds=1),now)=='stale'


def test_failed_ingest_does_not_mark_sensor_healthy(tmp_path):
    client,_=client_for(tmp_path)
    assert post_event(client, payload(source_ip='invalid')).status_code == 422
    assert client.get('/api/v1/sensors',headers=auth()).json()['sensors'][0]['status']=='never_seen'


def test_collector_restricts_heartbeat_target_and_treats_409_as_failure(monkeypatch):
    from sentinel.collectors import linux_ssh
    import pytest
    with pytest.raises(linux_ssh.CollectorError, match='Unapproved'):
        linux_ssh.send_signed(raw=b'{}',nonce='a'*32,sensor_id='lab-one',sensor_key=KEY,
                             host='127.0.0.1',port=8000,route='/api/v1/alerts')
    class Reply:
        status=409
        def read(self,n): return b''
    class FakeConnection:
        def __init__(self,*args,**kw):pass
        def request(self,*args,**kwargs): pass
        def getresponse(self):return Reply()
        def close(self):pass
    monkeypatch.setattr(linux_ssh.http.client,'HTTPConnection',FakeConnection)
    with pytest.raises(linux_ssh.CollectorError,match='HTTP 409'):
        linux_ssh.send_signed(raw=b'{"asset_id":"workstation-1"}',nonce='a'*32,
            sensor_id='lab-one',sensor_key=KEY,host='127.0.0.1',port=8000,route='/api/v1/sensors/heartbeat')


def test_unconfigured_sensor_cannot_forge_liveness(tmp_path):
    client,_=client_for(tmp_path)
    assert beat(client,sensor='unknown-sensor').status_code==401
    assert client.get('/api/v1/sensors',headers=auth()).json()['sensors'][0]['status']=='never_seen'


def test_event_and_heartbeat_update_status_with_single_sensor(tmp_path):
    client,_=client_for(tmp_path)
    assert post_event(client).status_code==202
    health=client.get('/api/v1/sensors',headers=auth()).json()['sensors'][0]
    assert health['status']=='healthy' and health['heartbeat_count']==0 and health['event_count']==1
    assert beat(client).status_code==202
    health=client.get('/api/v1/sensors',headers=auth()).json()['sensors'][0]
    assert health['event_count']==1 and health['heartbeat_count']==1
