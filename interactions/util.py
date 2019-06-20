# coding=utf8

import json


ACTIVITY_TAG = '[Activity]'
DIALOG_TAG = '[Dialog]'
POPUPWINDOW_TAG = '[PopupWindow]'
VIEW_TAG = '[ViewOnTouchEvent]'
EDITABLE_INPUT_CONNECTION_TAG = '[EditableInputConnection]'
SPANNER_STRING_BUILDER_TAG = '[SpannerStringBuilder]'
TEXT_VIEW_KEY_TAG = '[TextViewKeyboard]'


def extract_info(log):
    splits = log.split('-')
    tag = splits[0]
    package = splits[-1].strip()
    plid = int(splits[-2].strip())
    ts = splits[-3].strip()
    return {
        'tag': tag,
        'plid': plid,
        'package': package,
        'content': json.loads('-'.join(splits[1:-3]).strip())['payload'],
        'ts': ts
    }