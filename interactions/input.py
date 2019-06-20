# coding=utf8

from . import util
from . import event
from pprint import pprint


def infer_input(log_info):
    editable_address = dict()
    input_connection_count = 0
    m_begin_batch_edit_0 = list()
    for idx, lf in enumerate(log_info):
        if lf['tag'] == util.SPANNER_STRING_BUILDER_TAG:
            if 'address' in lf['content'] and lf['content']['address'] is not None:
                address = lf['content']['address']
                if address not in editable_address:
                    editable_address[address] = {
                        'length': 0,
                        'count': 0,
                        'index': [],
                        'match': 0
                    }
                editable_address[address]['count'] += 1
                editable_address[address]['length'] = max(editable_address[address]['length'], len(lf['content']['text']))
                editable_address[address]['index'].append(idx)
        elif lf['tag'] == util.EDITABLE_INPUT_CONNECTION_TAG:
            input_connection_count += 1
            if lf['content']['mBatchEditNesting'] == 0:
                m_begin_batch_edit_0.append(idx)

    print(editable_address)

    # Match
    pre_batch_edit_idx = 0
    for curr_batch_edit_idx in m_begin_batch_edit_0:
        for address, value in editable_address.items():
            for aidx in value['index']:
                if pre_batch_edit_idx < aidx < curr_batch_edit_idx:
                    value['match'] += 1
                    break
        pre_batch_edit_idx = curr_batch_edit_idx

    # Find max
    max_value = 0
    max_address_list = list()
    for address, value in editable_address.items():
        if value['match'] > max_value:
            max_value = value['match']
            max_address_list = [address]
        elif value['match'] == max_value:
            max_address_list.append(address)

    if len(max_address_list) == 0:
        return ''

    if len(max_address_list) == 1:
        return max_address_list[0]

    threshold = input_connection_count
    for address in max_address_list:
        editable_address[address]['count'] = abs(threshold - value['count'])

    # find min
    min_count = len(log_info)
    text_address = None
    text_length = 0
    for address in max_address_list:
        if editable_address[address]['count'] < min_count:
            min_count = editable_address[address]['count']
            text_address = address
            text_length = editable_address[address]['length']
        elif editable_address[address]['count'] == min_count:
            if editable_address[address]['length'] > text_length:
                text_address = address
                text_length = editable_address[address]['length']

    return text_address


def parse_input_event(msg_type, target, logs, nested_events, log_begin_idx):
    """
    Parse input event logs
    :params  msg_type
    :params  target
    :params  logs [Pair of (Down, Up)]
    :return: list of event.Event
    """
    log_info = [util.extract_info(log) for log in logs]
    plid, package = log_info[0]['plid'], log_info[0]['package']

    perform_editor_action = None
    string_info = list()
    text_view_id = None
    text_address = infer_input(log_info)
    print('Inferred Text Address: ', text_address)

    last_editable_input_connection_log = 0
    for idx, lf in enumerate(log_info):
        if lf['tag'] == util.SPANNER_STRING_BUILDER_TAG and 'address' in lf['content'] and lf['content']['address'] == text_address:
            string_info.append((idx, lf, last_editable_input_connection_log))
        elif lf['tag'] == util.EDITABLE_INPUT_CONNECTION_TAG:
            last_editable_input_connection_log = idx
            if lf['content']['event'] == 'performEditorAction':
                perform_editor_action = (idx, lf,)
            if text_view_id is None:
                text_view_id = lf['content']['TextViewId']
            assert text_view_id == lf['content']['TextViewId']

    text_view_info = {
        'classname': log_info[0]['content']['TextViewClassname'],
        'x': log_info[0]['content']['TextViewX'],
        'y': log_info[0]['content']['TextViewY'],
        'id': log_info[0]['content']['TextViewId'],
        'width': log_info[0]['content']['TextViewWidth'],
        'height': log_info[0]['content']['TextViewHeight'],
        'position_in_screen': log_info[0]['content']['TextViewPositionInScreen'],
        'TextView': log_info[0]['content']['TextView']
    }

    if perform_editor_action is not None:
        # add perform editor action in nested action
        editor_action_idx = perform_editor_action[0]
        text_view_info['position_in_screen'] = log_info[editor_action_idx]['content']['TextViewPositionInScreen']
        editor_action_event = event.InputEvent(
            plid=plid,
            package=package,
            log_begin_idx=editor_action_idx + log_begin_idx,
            msg_type=msg_type,
            target=target,
            begin_ts=log_info[editor_action_idx]['ts'],
            end_ts=log_info[editor_action_idx]['ts'],
            text_view_info=text_view_info,
            text=None,
            action=perform_editor_action[1]['content']['actionCode']
        )
        idx = 0
        for ne in nested_events:
            if editor_action_event.log_begin_idx < ne.log_begin_idx:
                # insert
                nested_events.insert(idx, editor_action_event)
                break
            idx += 1
        else:
            nested_events.append(editor_action_event)

    if len(string_info) == 0:
        return nested_events

    pprint(string_info)

    begin_ts = log_info[0]['ts']

    event_list = list()

    previous_idx = 0
    for ne_idx, ne in enumerate(nested_events):

        if ne.msg_type == event.Event.KEY_EVENT:
            if not ne.is_back():
                continue

        anchor = ne.log_begin_idx
        # find sublist
        last_idx = len(string_info)
        for idx, si in enumerate(string_info):
            if si[0] + log_begin_idx > anchor:
                last_idx = idx
                break
        sub_list = string_info[previous_idx:last_idx]
        previous_idx = last_idx

        if len(sub_list) > 0:
            string_input = ''
            string_log_begin_idx = sub_list[-1][0] + log_begin_idx
            for si in reversed(sub_list):
                text = si[1]['content']['text']
                if len(text) != 0:
                    string_input = text
                    # TextView location may changed due to the change of softkeyboard
                    text_view_info['position_in_screen'] = log_info[si[2]]['content']['TextViewPositionInScreen']
                    end_ts = si[1]['ts']
                    string_log_begin_idx = si[0] + log_begin_idx
                    break
            else:
                end_ts = string_info[last_idx - 1][1]['ts']

            event_list.append(
                event.InputEvent(
                    plid=plid,
                    package=package,
                    log_begin_idx=string_log_begin_idx,
                    msg_type=msg_type,
                    target=target,
                    begin_ts=begin_ts,
                    end_ts=end_ts,
                    text_view_info=text_view_info,
                    text=string_input,
                    action=None
                )
            )

        begin_ts = ne.end_ts
        event_list.append(ne)

        if ne.msg_type == event.Event.TYPE_EVENT and ne.action_type == event.InputEvent.ENTER_ACTION:
            for _ne in nested_events[ne_idx+1:]:
                if _ne.msg_type == event.Event.KEY_EVENT:
                    if not _ne.is_back():
                        continue
                event_list.append(_ne)
            break
    print(event_list)

    if len(nested_events) == 0:
        last_text = string_info[previous_idx:][-1]
        begin_ts = end_ts = last_text[1]['ts']
        event_list.append(
            event.InputEvent(
                plid=plid,
                package=package,
                log_begin_idx=last_text[0] + log_begin_idx,
                msg_type=msg_type,
                target=target,
                begin_ts=begin_ts,
                end_ts=end_ts,
                text_view_info=text_view_info,
                text=last_text[1]['content']['text'],
                action=None
            )
        )

    # if previous_idx < len(string_info):
    #     # Text Remained
    #     last_text = string_info[previous_idx:][-1]
    #     begin_ts = end_ts = last_text[1]['ts']
    #     event_list.append(
    #         event.InputEvent(
    #             log_begin_idx=last_text[0] + log_begin_idx,
    #             msg_type=msg_type,
    #             target=target,
    #             begin_ts=begin_ts,
    #             end_ts=end_ts,
    #             text_view_info=text_view_info,
    #             text=last_text[1]['content']['text'],
    #             action=None
    #         )
    #     )
    return event_list
