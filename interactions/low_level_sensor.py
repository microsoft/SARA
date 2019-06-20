# coding=utf8

from . import event, util

def parse_low_level_sensor_event(msg_type, target, logs, log_begin_idx):
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
    values = content['values']
    sensor_type = content['sensorType']
    listener_classname = content['className']

    return event.LowLevelSensorEvent(
        plid=plid,
        package=package,
        msg_type=msg_type,
        log_begin_idx=log_begin_idx,
        begin_ts=begin_ts,
        end_ts=end_ts,
        target=target,
        values=values,
        sensor_type=sensor_type,
        listener_classname=listener_classname
    )