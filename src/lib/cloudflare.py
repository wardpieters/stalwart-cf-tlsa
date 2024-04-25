import CloudFlare


def get_zone_id(zone_name):
    try:
        cf = CloudFlare.CloudFlare()
        zones = cf.zones.get(params={'name': zone_name, 'status': 'active'})
        return zones[0]['id']
    except:
        return None


def get_dns_record(zone_id, record_name, tlsa_type):
    try:
        cf = CloudFlare.CloudFlare()
        dns_records = cf.zones.dns_records.get(zone_id, params={'name': record_name, 'type': 'TLSA', 'comment': 'stalwart-cf-tlsa'})

        for record in dns_records:
            data = record['data']
            if data['usage'] == tlsa_type and data['matching_type'] == 1 and data['selector'] == 1:
                return record
    except:
        return None


def update_dns_record(zone_id, record_id, record_name, record_value):
    try:
        cf = CloudFlare.CloudFlare()
        cf.zones.dns_records.put(zone_id, record_id, data={'name': record_name, 'type': 'TLSA', 'data': record_value, 'comment': 'stalwart-cf-tlsa'})
    except:
        return None


def create_dns_record(zone_id, record_name, record_value):
    try:
        cf = CloudFlare.CloudFlare()
        cf.zones.dns_records.post(zone_id, data={'name': record_name, 'type': 'TLSA', 'data': record_value, 'comment': 'stalwart-cf-tlsa'})
    except:
        return None
