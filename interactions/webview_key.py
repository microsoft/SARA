# coding=utf8

import json
from . import util, event


def parse_key_event(msg_type, target, logs, log_begin_idx):
    """
    Parse WebViewKeyEvent event logs
    :params  msg_type
    :params  target
    :return: an instance of event.WebViewKeyEvent
    """

    assert len(logs) == 1
    log_info = util.extract_info(logs[0])
    plid, package = log_info['plid'], log_info['package']
    content = json.loads(log_info['content']['message'].split('[Frida]-')[1])

    begin_ts = log_info['ts']
    end_ts = log_info['ts']
    webview = content['webview']
    text = content['text']
    key_code = content['keyCode']
    class_list = list()
    for idx, c in content['targetClassList'].items():
        class_list.append(c)
    input_attrs = {
        'tag': content['targetTag'],
        'id': content['targetId'],
        'class_list': class_list,
        'type': content['inputType'],
        'name': content['inputName'],
    }

    return event.WebViewKeyEvent(
        plid=plid,
        package=package,
        log_begin_idx=log_begin_idx,
        msg_type=msg_type,
        target=target,
        begin_ts=begin_ts,
        end_ts=end_ts,
        key_code=key_code,
        input_attrs=input_attrs,
        text=text,
        webview=webview
    )