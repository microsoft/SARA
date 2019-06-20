# coding=utf8

from . import util
from . import event

def create_popup_window_event(msg_type, target, log, log_begin_idx):
    """
    Create a popupWindow event
    :params  msg_type
    :params  target
    :params  single log
    :return  an instance of event.TouchEvent
    """
    log_info = util.extract_info(log)
    plid, package = log_info['plid'], log_info['package']
    content = log_info['content']
    return event.PopupWindowEvent(
        plid=plid,
        package=package,
        log_begin_idx=log_begin_idx,
        msg_type=msg_type,
        target=target,
        begin_ts=log_info['ts'],
        end_ts=log_info['ts'],
        action=content['action']
    )