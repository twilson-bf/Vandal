"""Bounded geolocation for an explicitly requested scan target."""
import ipaddress
import json
import os
from urllib.request import urlopen
from .db import connect, now


def locate(engagement, ip):
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {'status':'skipped', 'reason':'Non-public address', 'ip':ip}
    if os.getenv('VANDAL_GEOIP_CITY'):
        import geoip2.database
        with geoip2.database.Reader(os.environ['VANDAL_GEOIP_CITY']) as reader:
            result = reader.city(ip)
        data = {'country':result.country.name, 'city':result.city.name,
                'latitude':result.location.latitude, 'longitude':result.location.longitude}
        source = 'local GeoIP'
    else:
        with urlopen('https://ipwho.is/' + str(address), timeout=10) as response:
            data = json.loads(response.read(100000))
        if data.get('success') is not True or data.get('ip') != str(address):
            raise ValueError(data.get('message', 'Geolocation lookup failed'))
        source = 'ipwho.is'
    lat, lon = float(data['latitude']), float(data['longitude'])
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise ValueError('Invalid geolocation coordinates')
    with connect() as con:
        con.execute("UPDATE assets SET country=?,city=?,latitude=?,longitude=?,geo_source=? WHERE engagement_id=? AND kind='ip' AND value=?",
            (data.get('country') or 'Unknown', data.get('city') or '', lat, lon, source, engagement, ip))
        network = data.get('connection') or {}
        if network.get('asn'):
            con.execute("UPDATE assets SET asn=?,provider=? WHERE engagement_id=? AND kind='ip' AND value=?",
                ('AS'+str(network['asn']), network.get('org') or network.get('isp') or '', engagement, ip))
    return {'status':'completed', 'source':source, 'looked_up_at':now(), 'ip':ip, 'response':data}
