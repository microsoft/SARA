# coding=utf8

from . import event, util


def parse_page_loaded(msg_type, target, logs, log_begin_idx):
    """
    Parse WebViewPageLoadedEvent event logs
    :params  msg_type
    :params  target
    :return: an instance of event.WebViewPageLoadedEvent
    """
    assert len(logs) == 1
    log_info = util.extract_info(logs[0])
    plid, package = log_info['plid'], log_info['package']
    content = log_info['content']
    begin_ts = log_info['ts']
    end_ts = log_info['ts']
    webview = content['webview']
    url = content['url']
    classname = content['clientClassname']

    return event.WebViewPageLoadedEvent(
        plid=plid,
        package=package,
        msg_type=msg_type,
        begin_ts=begin_ts,
        end_ts=end_ts,
        target=target,
        webview=webview,
        url=url,
        log_begin_idx=log_begin_idx,
        client_classname=classname
    )