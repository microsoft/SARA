# coding=utf8

from . import event, util

def parse_location_sensor_event(msg_type, target, logs, log_begin_idx):
    """
    Parse LowLevelSensorEvent event logs
    :params msg_type
    :params target
    :params logs
    :return: an instance of event.LowLevelSensorEvent
    """
    assert len(logs) == 1
    log_info = util.extract_info(logs[0])
    plid, package = log_info['plid'], log_info['package']
    content = log_info['content']
    begin_ts = log_info['ts']
    end_ts = log_info['ts']
    target = content['target']
    location_info = content['location']
    classname = content['className']
    provider = content['provider']

    return event.LocationEvent(
        plid=plid,
        package=package,
        msg_type=msg_type,
        log_begin_idx=log_begin_idx,
        begin_ts=begin_ts,
        end_ts=end_ts,
        target=target,
        location_info=location_info,
        classname=classname,
        provider=provider
    )