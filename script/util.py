# coding=utf8

"""
Tool Set
"""

import json
import re, bs4
from lxml import etree
from bs4 import BeautifulSoup
from . import parse_view_hierarchy as view_hierarchy_parser


BOUND_PATTERN = re.compile(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]')
FOCUSED_WINDOW_PATTERN = re.compile(r"^\s*FocusedWindow:\sname='(.*)'", re.M)


def get_bounds(left, top, right, bottom):
    return '[%d,%d][%d,%d]' % (left, top, right, bottom)


def parse_bounds(bounds):
    """
    left, top, right, bottom
    """
    match = BOUND_PATTERN.match(bounds)
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4))


def save_xml(xml, name):
    content = xml.prettify("utf-8")
    with open(name, 'wb') as f:
        f.write(content)


def parse_xml(xml):
    if isinstance(xml, str):
        _xml = BeautifulSoup(xml, 'lxml')
    else:
        _xml = xml
    return _xml


def parse_lxml_xml(xml):
    return etree.fromstring(xml.encode())


def check_bounds_overlap(bounds_1, bounds_2):
    """
    Calculate the ratio of overlap
    """
    left_1, top_1, right_1, bottom_1 = bounds_1[0], bounds_1[1], bounds_1[2], bounds_1[3]
    left_2, top_2, right_2, bottom_2 = bounds_2[0], bounds_2[1], bounds_2[2], bounds_2[3]
    width_1 = right_1 - left_1
    height_1 = bottom_1 - top_1
    width_2 = right_2 - left_2
    height_2 = bottom_2 - top_2

    overlap_width = width_1 + width_2 - (max(left_1 + width_1, left_2 + width_2) - min(left_1, left_2))
    overlap_height = height_1 + height_2 - (max(top_1 + height_1, top_2 + height_2) - min(top_1, top_2))

    if overlap_height <= 0 or overlap_width <= 0:
        return False
    
    overlap_area = overlap_height * overlap_width
    bounds_1_area = width_1 * height_1
    bounds_2_area = width_2 * height_2
    ratio = overlap_area / (bounds_1_area + bounds_2_area - overlap_area)
    return ratio


def find_view(resource_id, bounds, xml):
    """
    find UI View
    :param resource_id 'package_name:id/name'
    :param bounds '[left,top][right,bottom]'
    :param xml bs4 object or xml
    :return list of matched view
    """
    _xml = parse_xml(xml)
    matched_view = list()

    if len(resource_id) == 0:
        # Empty resource_id, then find with bounds
        matches = _xml.findAll(attrs={'bounds': bounds, 'focused': 'true'})
        if len(matches) == 0:
            return None
        return matches[0]
    else:
        matches = _xml.findAll(attrs={'resource-id': re.compile('^%s$' % resource_id, re.I)})
        for match in matches:
            target_bounds = match['bounds']
            print(target_bounds)
            overlapped_ratio = check_bounds_overlap(parse_bounds(bounds), parse_bounds(target_bounds))
            if overlapped_ratio > 0.5:
                matched_view.append((overlapped_ratio, match,))
        matched_view.sort(key=lambda x: x[0], reverse=True)
        if len(matched_view) == 0 or matched_view[0][1]['focused'] == 'false':
            return None
        return matched_view[0][1]


def find_soft_key(name, xml, is_samsung=False):
    """
    find key position in soft keyboard
    """
    _xml = parse_xml(xml)
    print(is_samsung)
    if is_samsung:
        keys = _xml.findAll(attrs={'package': 'com.google.android.inputmethod.latin', 'content-desc': re.compile("^%s$" % name, re.I)})
    else:
        keys = _xml.findAll(attrs={'class': 'com.android.inputmethod.keyboard.Key', 'content-desc': re.compile("^%s$" % name, re.I)})
    if len(keys) == 0:
        return None
    assert len(keys) == 1
    bounds = keys[0].attrs["bounds"]
    match = BOUND_PATTERN.match(bounds)
    left, top, right, bottom = int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4))
    width = right - left
    height = bottom - top
    return left + width/2, top + height/2


def check_soft_keyboard(xml):
    """
    Check whether soft keyboard exists
    """
    _xml = parse_xml(xml)
    keys = _xml.findAll(attrs={'class': 'com.android.inputmethod.keyboard.Key'})
    if len(keys) > 0:
        return True
    return False


def get_current_window(d):
    input_state = d.shell('dumpsys input')[0]
    matches = FOCUSED_WINDOW_PATTERN.findall(input_state)
    if len(matches) == 0:
        return None
    window = matches[0]
    if 'popupwindow' in window.lower():
        return window
    return None


def dump_view_hierarchy(d, filename):
    """
    Dump view hierarchy from adb shell dumpsys activity top
    """
    activity_info = d.shell('dumpsys activity top')[0]
    hierarchy = view_hierarchy_parser.read_view_hierarchy(activity_info)
    with open(filename, 'wb') as f:
        f.write(etree.tostring(hierarchy, pretty_print=True))
    return BeautifulSoup(etree.tostring(hierarchy, pretty_print=True).decode(), 'lxml'), hierarchy


def get_view_hierarchy_component_bounds(component):
    """
    :param component, lxml element
    """
    parent = component
    elements = list()
    while parent is not None:
        elements.append(parent)
        parent = parent.getparent()

    width, height = int(component.attrib['right']) - int(component.attrib['left']), int(component.attrib['bottom']) - int(component.attrib['top'])
    elements.reverse()
    left, top = 0, 0
    for element in elements:
        if 'left' in element.attrib and len(element.attrib['left']) > 0:
            left += int(element.attrib['left'])
            top += int(element.attrib['top'])
    return get_bounds(left, top, left + width, top + height)


def dfs(tag, source_x, source_y, matched, parent_left, parent_top):
    """
    Depth First Search on View hierarchy
    """
    v_left, v_top, v_right, v_bottom = int(tag['left']), int(tag['top']), int(tag['right']), int(tag['bottom'])
    width, height = v_right - v_left, v_bottom - v_top
    abs_left, abs_top = parent_left + v_left, parent_top + v_top
    abs_right, abs_bottom = width + abs_left, abs_top + height

    is_visible = tag['visible'] == 'true'
    is_enable = tag['enabled'] == 'true'
    if is_visible and abs_left <= source_x <= abs_right and abs_top <= source_y <= abs_bottom:
        children_feedback = list()
        for child in tag.children:
            if isinstance(child, bs4.element.Tag):
                fb = dfs(child, source_x, source_y, matched, abs_left, abs_top)
                children_feedback.append(fb)
                if tag['address'] == '4704841':
                    print(abs_left, abs_top)
                    print(fb, child)
                    print('===')
                # children_feedback.append(dfs(child, source_x, source_y, matched, abs_left, abs_top))
        if list(children_feedback) == 0:
            # Leaf node
            matched.append((tag, abs_left, abs_top,))
            return True
        # Inner node
        result = False
        for fb in children_feedback:
            result |= fb
        if result:
            # True, i.e., some child match, and add child itself
            return True
        else:
            # No child match, then add tag itself
            matched.append((tag, abs_left, abs_top,))
            return True
    else:
        return False


def get_view_info(tag, abs_left, abs_top):
    v_left, v_top, v_right, v_bottom = int(tag['left']), int(tag['top']), int(tag['right']), int(tag['bottom'])
    is_visible = tag['visible'] == 'true'
    is_enable = tag['enabled'] == 'true'
    is_clickable = tag['clickable'] == 'true'
    scroll_horiz = tag['scroll_horiz'] == 'true'
    scroll_verti = tag['scroll_verti'] == 'true'
    return {
        'rid': tag['resource_id'],
        'vid': tag['view_id'],
        'classname': tag['classname'],
        'address': tag['address'],
        'left': v_left,
        'top': v_top,
        'right': v_right,
        'bottom': v_bottom,
        'is_visible': is_visible,
        'is_enable': is_enable,
        'is_clickable': is_clickable,
        'abs_left': abs_left,
        'abs_top': abs_top,
        'abs_right': abs_left + (v_right - v_left),
        'abs_bottom': abs_top + (v_bottom - v_top),
        'scroll_horiz': scroll_horiz,
        'scroll_verti': scroll_verti,
    }


def find_component_candidates(view_hierarchy, source_x, source_y):
    root = view_hierarchy.find('view')
    matched_views = list()
    dfs(root, source_x, source_y, matched_views, 0, 0)
    return [get_view_info(v[0], v[1], v[2]) for v in matched_views]


def instrument_view(classname_list, address_list, action_count):
    hook_code = """
        Java.perform(function(){
            var classnameList = [%s];
            var addressList = [%s];
            var action_count = %d;
            send({
                list: classnameList,
                addressList: addressList
            });
            var handleList = [];
            var Integer = Java.use('java.lang.Integer');
            var System = Java.use('java.lang.System');
            for(var i = 0; i < classnameList.length; i++){
                var cn = Java.use(classnameList[i]);
                var currentHandle = cn.dispatchTouchEvent.handle;
                var isInstrument = true;
                for(var j = 0; j < handleList.length; j++){
                    if(handleList[j] === currentHandle){
                        isInstrument = false;
                        break;
                    }
                }
                if(isInstrument){
                    handleList.push(currentHandle);
                    cn.dispatchTouchEvent.implementation = function(ev){
                        var detail = this.toString();
                        if(ev.getAction() === 0){
                            setTimeout(function(){
                                send({view: detail, action_count: action_count});
                            }, 0);
                        }
                        return this.dispatchTouchEvent(ev);
                    }
                }
            }
        });
    """ % ((', '.join(['"' + cn + '"' for cn in classname_list])), (', '.join(['"' + a + '"' for a in address_list])), action_count)
    return hook_code


# Instrument WebView
def instrument_WebView():
    hook_code = """
        Java.perform(function(){
            var WebView = Java.use('android.webkit.WebView');
            WebView.setWebViewClient.implementation = function(client){
                send({
                    'webview': ''+this,
                    'webviewHandle': this.$handle,
                    'webviewClient': ''+client,
                    'clientClassname': client.$className,
                });
                return this.setWebViewClient(client);
            }
        });
    """
    return hook_code


def webview_set_text(selector, text, classname, address, package_name):
    """
    :param selector: input element selector
    :param text: value of input element
    :param classname: classname of webview
    :param address: address of webview
    """
    inject_js = """
        var __frida_setText = function(text, selector){
            var elements = document.querySelectorAll(selector);
            var focusedInput = null;
            for(var i = 0; i < elements.length; i++){
                if(elements[i] === document.activeElement){
                    focusedInput = elements[i];
                    break;
                }
            }
            if(focusedInput){
                focusedInput.value = text;
            }
        };
    """
    inject_js = re.sub(r'\s{2,}', '', inject_js)
    hook_code = """
        Java.perform(function(){
            // Cast WebView Instance
            var address = '%s';
            var className = '%s';
            Java.choose(className, {
                onMatch: function(webview){
                    var detail = webview.toString();
                    if(detail.includes(address)){
                        send({webview: detail, msg: 'Found'});
                        setTimeout(
                            function(){
                                Java.perform(function(){                                    
                                    Java.scheduleOnMainThread(function(){
                                        var injectedScript = '%s';
                                        var text = '%s';
                                        var selector = '%s';
                                        webview.loadUrl('javascript:'+injectedScript);
                                        var jsUrl = "javascript:__frida_setText('" + text + "', '" + selector + "')";
                                        webview.loadUrl(jsUrl);
                                    });
                                });
                            }, 0
                        );
                        return 'stop';
                    }
                },
                onComplete: function(instance){
                    send({msg: 'Complete'});
                }
            });
        });
    """ % (address, classname, inject_js, text, selector)
    return hook_code


def get_view_address(view_str):
    return view_hierarchy_parser.get_view_address(view_str)


# Debug
def instrument_chrome_client():
    hook_code = """
        Java.perform(function(){
            var Client = Java.use('org.wordpress.android.util.helpers.WPWebChromeClient');
            Client.onConsoleMessage.overload('android.webkit.ConsoleMessage').implementation = function(console){
                var msgFromConsole = console.message();
                send({
                    message: msgFromConsole
                });
                return this.onConsoleMessage(console);
            };
        });
    """
    return hook_code


def instrument_low_level_sensors(listener_classname_dict):
    hook_template = """
        var _className = '%s';
        var className = Java.use(_className);
        var mockValues = '%s';
        mockValues = JSON.parse(mockValues);
        className.onSensorChanged.implementation = function(sensorEvent){
            var stype = sensorEvent.sensor.value.getStringType();
            if(mockValues.hasOwnProperty(stype)){
                var index = mockValues[stype].index
                if(index < mockValues[stype].values.length){
                    sensorEvent.values.value = mockValues[stype].values[index]
                    mockValues[stype].index += 1
                }else{
                    sensorEvent.values.value = mockValues[stype].values[index-1]
                }
                // send({
                //     msg: 'Inject recorded values', 
                //    value: sensorEvent.values.value
                // })
            }
            return this.onSensorChanged(sensorEvent);
        };
    """
    code = list()
    for classname, sensors in listener_classname_dict.items():
        code.append(hook_template % (classname, json.dumps(sensors)))
    hook_code = """
        Java.perform(function(){
            %s
        })
    """ % '\n'.join(code)
    return hook_code


def instrument_getlastknownlocation(get_location_classname_dict):
    hook_template = """
        var _className = '%s';
        var className = Java.use(_className);
        var mockValues = '%s';
        mockValues = JSON.parse(mockValues);
        className.getLastKnownLocation.implementation = function(provider){
            console.log('getLastKnownLocation....')
            var location = this.getLastKnownLocation(provider);
            if(location === null){
                return location;
            }
            if(mockValues.hasOwnProperty(provider)){
                var index = mockValues[provider].index;
                if(index >= mockValues[provider].values.length){
                    index = mockValues[provider].values.length - 1;
                }
                var value = mockValues[provider].values[index];
                location.mLatitude = value.latitude;
                location.mLongitude = value.longitude;
                location.mBearing = value.bearing;
                location.mSpeed = value.speed;
                location.mAltitude = value.altitude;
                location.mAccuracy = value.accuracy;
                send({
                    msg: 'Inject recorded values', 
                    value: location.getLatitude()
                });
            }
            return location;
        };
    """
    code = list()
    for classname, providers in get_location_classname_dict.items():
        code.append(hook_template % (classname, json.dumps(providers)))
    hook_code = """
        Java.perform(function(){
            %s
        })
    """ % '\n'.join(code)
    return hook_code


def instrument_onlocationchanged(on_location_classname_dict):
    hook_template = """
        var _className = '%s';
        var className = Java.use(_className);
        var mockValues = '%s';
        mockValues = JSON.parse(mockValues);
        className.onLocationChanged.implementation = function(location){
            if(location === null){
                return this.onLocationChanged(location);
            }

            var index = mockValues.index;
            if(index >= mockValues.values.length){
                index = mockValues.values.length - 1;
            }
            var value = mockValues.values[index];
            location.mLatitude = value.latitude;
            location.mLongitude = value.longitude;
            location.mBearing = value.bearing;
            location.mSpeed = value.speed;
            location.mAltitude = value.altitude;
            location.mAccuracy = value.accuracy;
            // send({
            //    msg: 'Inject recorded values', 
            //    value: location.getLatitude()
            // });
            return this.onLocationChanged(location);
        };
    """
    code = list()
    for classname, values in on_location_classname_dict.items():
        code.append(hook_template % (classname, json.dumps(values)))
    hook_code = """
        Java.perform(function(){
            %s
        })
    """ % '\n'.join(code)
    return hook_code


"""
Widget replay
"""

def px2dp(px, dpi):
    return (px * 160) / dpi


def dp2px(dp, dpi):
    return dp * (dpi / 160)


def get_target_coordinate(bounds, x_offset_dp, y_offset_dp, target_dpi):
    """
    :param component: etree element
    """
    if isinstance(bounds, str):
        left, top, right, bottom = parse_bounds(bounds)
    else:
        left, top, right, bottom = bounds['left'], bounds['top'], bounds['right'], bounds['bottom']

    left_dp, top_dp, right_dp, bottom_dp = px2dp(left, target_dpi), px2dp(top, target_dpi), px2dp(right, target_dpi), px2dp(bottom, target_dpi)
    
    target_x_dp, target_y_dp = left_dp + x_offset_dp, top_dp + y_offset_dp
    
    print('x: ', left_dp, target_x_dp, right_dp)
    print('y: ', top_dp, target_y_dp, bottom_dp)
    target_x_dp = right_dp - 5 if target_x_dp > right_dp else target_x_dp
    target_y_dp = bottom_dp - 5 if target_y_dp > bottom_dp else target_y_dp
    # assert left_dp <= target_x_dp <= right_dp and top_dp <= target_y_dp <= bottom_dp
    target_x, target_y = dp2px(target_x_dp, target_dpi), dp2px(target_y_dp, target_dpi)
    return target_x, target_y


def find_target_component(xml, target_signature, attrs):
    print(attrs)
    element = xml.findAll(attrs=attrs)
    print(len(element))
    assert len(element) == 1
    element = element[0]

    el = element.findAll(attrs=target_signature)
    print('Target Signature: ', target_signature)
    if len(el) == 0:
        for parent in element.parents:
            if 'resource-id' in parent.attrs:
                for k, v in target_signature.items():
                    if parent[k] != v:
                        break
                else:
                    return parent
            el = parent.findAll(attrs=target_signature)
            if len(el) > 0:
                print(len(el))
                return el[0]
        return None
    else:
        return el[0]