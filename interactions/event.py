# coding=utf8

import json

class Event:

    TOUCH_EVENT = 'touch'
    KEY_EVENT = 'key'
    ACTION_EVENT = 'action'
    TEXT_EVENT = 'text'
    TYPE_EVENT = 'type'
    WEBVIEW_KEY_EVENT = 'webview_key'
    WEBVIEW_PAGE_LOADED = 'webview_page_loaded'
    LOW_LEVEL_SENSOR_EVENT = 'sensor'
    LOCATION_EVENT = 'location'

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts):
        """
        :param plid, local process id
        :param pacakge, package name of the local process
        """
        # TODO: Refactor msg type
        if msg_type.lower() == 'touchevent':
            self._msg_type = self.TOUCH_EVENT
        elif msg_type.lower() == 'keyevent':
            self._msg_type = self.KEY_EVENT
        elif msg_type.lower() == 'action':
            self._msg_type = self.ACTION_EVENT
        elif msg_type.lower() == 'text':
            self._msg_type = self.TEXT_EVENT
        elif msg_type.lower() == 'type':
            self._msg_type = self.TYPE_EVENT
        elif msg_type.lower() == 'webviewkeyevent':
            self._msg_type = self.WEBVIEW_KEY_EVENT
        elif msg_type.lower() == 'webviewpageloaded':
            self._msg_type = self.WEBVIEW_PAGE_LOADED
        elif msg_type.lower() == 'sensorevent':
            self._msg_type = self.LOW_LEVEL_SENSOR_EVENT
        elif msg_type.lower() == 'lastknownlocation' or msg_type.lower() == 'locationevent':
            self._msg_type = self.LOCATION_EVENT
        else:
            raise Exception()

        self._log_begin_idx = log_begin_idx
        self._target = target
        self._begin_ts = begin_ts
        self._end_ts = end_ts
        self._plid = plid
        self._package = package

    @property
    def package(self):
        return self._package

    @property
    def plid(self):
        return self._plid

    @property
    def target(self):
        return self._target

    @property
    def msg_type(self):
        return self._msg_type

    @property
    def begin_ts(self):
        return self._begin_ts

    @property
    def end_ts(self):
        return self._end_ts

    @property
    def log_begin_idx(self):
        return self._log_begin_idx

    def transform(self):
        """
        Translate to uiautomator2 script
        Should be override
        """
        raise Exception('Event Transform should be override')

    def record_msg(self):
        """
        Return necessary msg to reproduce
        """
        return {
            'msg_type': self.msg_type,
            'begin_ts': self.begin_ts,
            'end_ts': self.end_ts,
            'log_begin_idx': self.log_begin_idx,
            'package': self._package,
            'plid': self._plid
        }
    
    def __repr__(self):
        return self.__str__()


class KeyEvent(Event):

    HIDE_KEYBOARD_INTENT = 'HideSoftKeyboard'

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, key_code, down_time, intent=None):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._key_code = key_code
        self._down_time = down_time
        self._intent = None
    
    @property
    def key_code(self):
        return self._key_code
    
    @property
    def down_time(self):
        return self._down_time

    @property
    def intent(self):
        return self._intent
    
    @intent.setter
    def intent(self, i):
        self._intent = i
    
    def is_back(self):
        """
        Press back, Key Code of Back (4)
        """
        return self.key_code == 4

    def __str__(self):
        return json.dumps({
            'msg_type': self.msg_type,
            'begin_ts': self.begin_ts,
            'end_ts': self.end_ts,
            'event': 'KeyEvent',
            'key_code': self.key_code,
            'down_time': self.down_time,
            'intent': self.intent,
            'log_begin_idx': self.log_begin_idx
        })
    
    def __repr__(self):
        return self.__str__()

    def transform(self):
        return 'd.press(%d)' % self.key_code

    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': 'KeyEvent',
            'key_code': self.key_code,
            'down_time': self.down_time,
            'intent': self.intent
        })
        return super_record


class TouchEvent(Event):

    SHORT_TAP = 'Tap'
    LONG_TAP = 'LongTap'

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, tap_type, x, y, duration, view_type):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._tap_type = tap_type
        self._x = x
        self._y = y
        self._duration = duration
        self._view_type = view_type
        self._event_type = 'TouchEvent'

    @property
    def event_type(self):
        return self._event_type
    
    @property
    def tap_type(self):
        return self._tap_type
    
    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y
    
    @property
    def duration(self):
        return self._duration / 1000
    
    @property
    def view_type(self):
        return self._view_type
    
    def __str__(self):
        return json.dumps(self.record_msg())
    
    def __repr__(self):
        return self.__str__()

    def transform(self):
        action_click = 'd.click(' + str(self.x) + ', ' + str(self.y) + ')'
        action_longclick = 'd.long_click(' + str(self.x) + ', ' + str(self.y) + ')'
        return action_click if self.tap_type == 'Tap' else action_longclick

    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': self.event_type,
            'target': self.target,
            'tap_type': self.tap_type,
            'x': self.x,
            'y': self.y,
            'view_type': self.view_type,
            'duration': self.duration,
        })
        return super_record


class SwipeEvent(Event):

    SWIPE = 'Swipe'
    DRAG = 'Drag'

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, motion_type, from_x, from_y, to_x, to_y, pointers, time_interval):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._motion_type = motion_type
        self._from_x = from_x
        self._from_y = from_y
        self._to_x = to_x
        self._to_y = to_y
        self._pointers = pointers
        self._time_interval = time_interval
        self._event_type = 'SwipeEvent'

    @property
    def event_type(self):
        return self._event_type
    
    @property
    def motion_type(self):
        return self._motion_type
    
    @property
    def from_x(self):
        return self._from_x
    
    @property
    def from_y(self):
        return self._from_y

    @property
    def to_x(self):
        return self._to_x
    
    @property
    def to_y(self):
        return self._to_y

    @property
    def pointers(self):
        return self._pointers

    @property
    def time_interval(self):
        return self._time_interval

    def __str__(self):
        return json.dumps(self.record_msg())

    def __repr__(self):
        return self.__str__()

    def transform(self):
        # action_swipe = 'd.swipe(' + str(self.from_x) +',' + str(self.from_y) + ', ' + str(self.to_x) +', ' + str(self.to_y) + ')'
        # action_drag = 'd.drag(' + str(self.from_x) +',' + str(self.from_y) + ', ' + str(self.to_x) +', ' + str(self.to_y) + ')'
        # return action_swipe if self.motion_type == 'Swipe' else action_drag
        return 'd.swipe_points(%s, %f)' % (str(self.pointers), 0.01)
    
    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': 'SwipeEvent',
            'target': self.target,
            'type': self.motion_type,
            'from_x': self.from_x,
            'from_y': self.from_y,
            'to_x': self.to_x,
            'to_y': self.to_y,
            'time_interval': self.time_interval,
            'points': self.pointers,
            'log_begin_idx': self.log_begin_idx
        })
        return super_record


class InputEvent(Event):

    TYPE_ACTION = 'TYPE'
    ENTER_ACTION = 'ENTER'
    HIDE_ACTION = 'HIDE'

    EDITOR_ACTION_MAP = {
        '2': 'go',
        '3': 'search',
        '4': 'send',
        '5': 'next',
        '6': 'done',
        '7': 'previous'
    }

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, text_view_info, text=None, action=None):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._text_view_info = text_view_info
        if text is None:
            self._action_type = self.ENTER_ACTION
            self._action = action
            self._text = None
        else:
            self._action_type = self.TYPE_ACTION
            self._text = text
            self._action = None

    @property
    def text_view_info(self):
        return self._text_view_info

    @property
    def text(self):
        return self._text

    @property
    def action(self):
        return self._action
    
    @property
    def action_type(self):
        return self._action_type

    def __str__(self):
        return json.dumps(self.record_msg())

    def __repr__(self):
        return self.__str__()

    def get_text_view_id(self):
        if self.text_view_info is None:
            return None
        return self.text_view_info['id']

    def get_text_view_resource_id(self):
        """
        Derive from the android.view.View.toString
        """
        if self.text_view_info is not None:
            try:
                text_view_id = int(self.text_view_info['id'])
            except:
                return None
            detail =  self.text_view_info['TextView']
            hex_text_view_id = '#'+hex(text_view_id)[2:]

            index = detail.find(hex_text_view_id)
            if index == -1:
                return None
            resource_id = detail[index+len(hex_text_view_id):].strip()[:-1]
            if len(resource_id) == 0:
                return None
            return resource_id
        return None
    
    def get_text_view_bounds(self):
        if self.text_view_info is not None:
            position_in_screen = self.text_view_info['position_in_screen']
            left, top = position_in_screen[0], position_in_screen[1]
            width = int(self.text_view_info['width'])
            height = int(self.text_view_info['height'])
            return '[%d,%d][%d,%d]' % (left, top, left+width, top+height)
        return None

    def get_editor_action(self):
        if self.action_type == self.ENTER_ACTION:
            action = str(self.action)
            if action not in self.EDITOR_ACTION_MAP:
                return None
            return self.EDITOR_ACTION_MAP[action]
        return None

    def transform(self):
        if self.action_type == self.ENTER_ACTION:
            return 'd.press("enter")'
        elif self.action_type == 'TYPE':
            # "android.support.v7.widget.AppCompatEditText{4446901 VFED..CL. .F...... 0,29-1028,155 #7f0f00f2 app:id/input_account_name}
            # resource_id = self.text_view_info
            return 'd.set_text('+ '\'' + self.text + '\'' + ')'

    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': 'InputEvent',
            'target': self.text_view_info['classname'],
            'text': self.text,
            'action_type': self.action_type,
            'action_code': self.action,
            'action_code_name': self.get_editor_action(),
            'text_view_rid': self.get_text_view_resource_id(),
            'text_view_bounds': self.get_text_view_bounds(),
            'text_view_id': self.get_text_view_id(),
            'log_begin_idx': self.log_begin_idx
        })
        return super_record


class PopupWindowEvent(Event):

    HIDE = 'hide'
    SHOW = 'show'

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, action):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        if action == 'hide':
            self._action = self.HIDE
        else:
            self._action = self.SHOW
    
    @property
    def action(self):
        return self._action

    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'action': self.action,
            'event': 'PopupWindowEvent',
            'target': self.target,
        })
        return super_record

    def __str__(self):
        return json.dumps(self.record_msg())
    
    def __repr__(self):
        return self.__str__()
    
    def transform(self):
        pass


class WebViewKeyEvent(Event):

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, webview, text, input_attrs, key_code=None):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._input_attrs = input_attrs
        self._webview = webview
        self._text = text
        self._key_code = key_code
    
    @property
    def webview(self):
        return self._webview

    @property
    def input_attrs(self):
        return self._input_attrs

    @property
    def text(self):
        return self._text
    
    @property
    def key_code(self):
        return self._key_code

    def get_webview_class(self):
        """
        If it matches pattern then return extracted classname, otherwise return default name 
        """
        # android.webkit.WebView{4aece6 VFEDHVC.. .F...... 0,112-720,610 #7f090691 app:id/webView}
        idx = self.webview.find('{')
        if idx != -1:
            return self.webview[:idx]
        else:
            return 'android.webkit.WebView'
    
    def generate_query_selector(self):
        eid = self.input_attrs['id']
        if len(eid) != 0:
            return '#'+eid
        selector = self.input_attrs['tag'].lower()
        if len(self.input_attrs['class_list']) > 0:
            selector += '.' + '.'.join(self.input_attrs['class_list'])
        if len(self.input_attrs['name']) > 0:
            selector += '[name="%s"]' % self.input_attrs['name']
        if len(self.input_attrs['type']) > 0:
            selector += '[type="%s"]' % self.input_attrs['type']
        return selector

    def __str__(self):
        return json.dumps(self.record_msg())

    def transform(self):
        return 
    
    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': 'WebViewKeyEvent',
            'text': self.text,
            'target': self.target,
            'key_code': self.key_code,
            'webview': self.webview
        })
        super_record.update(self._input_attrs)
        return super_record


class WebViewPageLoadedEvent(Event):

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, webview, url, client_classname):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._webview = webview
        self._url = url
        self._client_classname = client_classname
    
    @property
    def webview(self):
        return self._webview
    
    @property
    def url(self):
        return self._url

    @property
    def client_classname(self):
        return self._client_classname

    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': 'WebViewPageLoaded',
            'url': self.url,
            'target': self.target,
            'client_classname': self._client_classname
        })
        return super_record

    def __str__(self):
        return json.dumps(self.record_msg())
    
    def transform(self):
        pass


class LowLevelSensorEvent(Event):

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, values, sensor_type, listener_classname):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._values = values
        self._sensor_type = sensor_type
        self._listener_classname = listener_classname

    @property
    def values(self):
        return self._values
    
    @property
    def sensor_type(self):
        return self._sensor_type

    @property
    def listener_classname(self):
        return self._listener_classname

    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': 'LowLevelSensorEvent',
            'values': self.values,
            'sensor_type': self.sensor_type,
            'listener_classname': self.listener_classname
        })
        return super_record
    
    def __str__(self):
        return json.dumps(self.record_msg())

    def transform(self):
        pass


class LocationEvent(Event):

    GET_LAST_KNOWN_LOCATRION = 0
    ON_LOCATION_CHANGED = 1

    def __init__(self, plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts, location_info, classname, provider):
        super().__init__(plid, package, log_begin_idx, msg_type, target, begin_ts, end_ts)
        self._location_info = location_info
        self._classname = classname
        self._provider = provider
        if msg_type.lower() == 'lastknownlocation':
            self._location_type = self.GET_LAST_KNOWN_LOCATRION
        else:
            self._location_type = self.ON_LOCATION_CHANGED

    @property
    def location_info(self):
        return self._location_info
    
    @property
    def location_type(self):
        return self._location_type

    @property
    def provider(self):
        return self._provider

    @property
    def classname(self):
        return self._classname

    def record_msg(self):
        super_record = super().record_msg()
        super_record.update({
            'event': 'LowLevelSensorEvent',
            'location_info': self.location_info,
            'location_type': self.location_type,
            'classname': self.classname,
            'provider': self.provider
        })
        return super_record
    
    def __str__(self):
        return json.dumps(self.record_msg())

    def transform(self):
        pass
