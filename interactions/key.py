# coding=utf8

from . import util, event


def create_key_event(msg_type, target, log, log_begin_idx):
    """
    Create a key event
    :params  msg_type
    :params  target
    :params  single log
    :return: an instance of event.KeyEvent
    """
    log_info = util.extract_info(log)
    plid, package = log_info['plid'], log_info['package']
    content = log_info['content']
    return event.KeyEvent(
        plid=plid,
        package=package,
        log_begin_idx=log_begin_idx,
        msg_type=msg_type,
        target=target,
        begin_ts=log_info['ts'],
        end_ts=log_info['ts'],
        key_code=content['keyCode'],
        down_time=content['downTime']
    )


def parse_key_event(msg_type, target, logs, log_begin_idx):
    """
    Parse key event logs
    :params  msg_type
    :params  target
    :params  logs [Pair of (Down, Up)]
    :return: an instance of event.KeyEvent
    """
    log_info = [util.extract_info(log) for log in logs]
    plid, package = log_info[0]['plid'], log_info[0]['package']
    contents = [log['content'] for log in log_info]

    # assert len(contents) == 2 or len(contents) == 1

    begin_ts = log_info[0]['ts']
    end_ts = log_info[-1]['ts']
    key_code = contents[0]['keyCode']
    down_time = contents[0]['downTime']

    return event.KeyEvent(
        plid=plid,
        package=package,
        log_begin_idx=log_begin_idx,
        msg_type=msg_type,
        target=target,
        begin_ts=begin_ts,
        end_ts=end_ts,
        key_code=key_code,
        down_time=down_time
    )
