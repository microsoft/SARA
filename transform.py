# coding=utf8

import re
import os
import bs4
import math
import json
import codecs
import argparse
from lxml import etree
from pprint import pprint
from bs4 import BeautifulSoup

# package_name = None
source_width, source_height, source_dpi = None, None, None
target_width, target_height, target_dpi = None, None, None

BOUND_PATTERN = re.compile(r'\[([-+]?\d+),([-+]?\d+)\]\[[-+]?(\d+),([-+]?\d+)\]')
VIEW_ATTR_PATTERN = re.compile(r'^(?P<classname>.*)\{(?P<address>.*)\s(?P<visible>.)(?P<focusable>.)(?P<enabled>.)(?P<draw_mask>.)(?P<scroll_horiz>.)(?P<scroll_verti>.)(?P<clickable>.)(?P<long_clickable>.)((?P<context_clickable>.)\s|\s)(.+)\s(?P<left>-?\d+),(?P<top>-?\d+)\-(?P<right>-?\d+),(?P<bottom>-?\d+)((\s(?P<view_id>#[a-zA-Z0-9]+)\s(?P<resource_id>.+))|(\s*(.*)))\}')
REPLAY_ACTION_PATTERN = re.compile(r'\[ReplayAction\]-(?P<action_count>\d+):\s+\[(?P<action>.*)\]\-(?P<info>.*)')
REPLAY_VIEW_INSTRUMENTATION_PATTERN = re.compile(r'\[ReplayViewInstrumentation\]:\s+(.*)')
REPLAY_TIME_INTERVAL_PATTERN = re.compile(r'\[ReplayTimeInterval\]-(\d+):\s+(.*)')


def replace_package_name(rid, package_name):
    if rid is None:
        return ''
    idx = rid.find(':id/')
    if idx == -1:
        return rid
    prefix = rid[:idx]
    if prefix.lower() == 'app':
        return package_name + rid[idx:]
    return rid


def parse_resolution(resolution):
    """
    return: width, height, resolution
    """
    resolution = resolution.strip()
    splits = resolution.split(',')
    return int(splits[0]), int(splits[1]), int(splits[2])


def parse_bounds(bounds):
    """
    left, top, right, bottom
    """
    match = BOUND_PATTERN.match(bounds)
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4))


def get_bounds(left, top, right, bottom):
    return '[%d,%d][%d,%d]' % (left, top, right, bottom)


def parse_view(line):
    view_str = line.strip()
    match = VIEW_ATTR_PATTERN.match(view_str)
    if match is None:
        return None
    view_attrs = dict()
    for attr in ['classname', 'address', 'visible', 'focusable', 'enabled', 'draw_mask', 'scroll_horiz', 'scroll_verti', 'clickable', 'long_clickable', 'context_clickable', 'left', 'top', 'right', 'bottom', 'view_id', 'resource_id']:
        if attr in ['visible', 'focusable', 'enabled', 'draw_mask', 'scroll_horiz', 'scroll_verti', 'clickable', 'long_clickable', 'context_clickable']:
            value = match.group(attr)
            if attr == 'visible':
                if value == 'V':
                    view_attrs[attr] = 'true'
                else:
                    view_attrs[attr] = 'false'
            else:
                if value == '.':
                    view_attrs[attr] = 'false'
                else:
                    view_attrs[attr] = 'true'
        else:
            view_attrs[attr] = match.group(attr)
    return view_attrs


def read_ui_xml(xml_file):
    with codecs.open(xml_file, 'r', encoding='utf8') as f:
        return BeautifulSoup(f.read(), 'lxml')


def lxml_read_ui_xml(xml_file):
    return etree.parse(xml_file)


def px2dp(px, dpi):
    return (px * 160) / dpi


def dp2px(dp, dpi):
    return dp * (dpi / 160)


def transform_coordinate(source_x, source_y):
    """
    source_x: pixel
    source_y: pixel
    """
    source_x_dp, source_y_dp = px2dp(source_x, source_dpi), px2dp(source_y, source_dpi)
    target_x, target_y = dp2px(source_x_dp, target_dpi), dp2px(source_y_dp, target_dpi)
    return target_x, target_y


def parse_action(log, match):
    action_count = int(match.group('action_count'))
    action = match.group('action')
    info = json.loads(match.group('info'))
    action_block = {
        'action_count': action_count,
        'action': action,
        'info': info,
        'plid': info['plid'],
        'package': info['package']
    }
    return action_block


def parse_instrumentation(log, match):
    info = json.loads(match.group(1))['payload']
    if 'action_count' not in info:
        return None
    return info


def parse_time_interval(log, match):
    action_count = int(match.group(1))
    info = json.loads(match.group(2))
    info['action_count'] = action_count
    return info


def parse_trace(trace_file):
    actions = list()
    instrumentations = list()
    time_intervals = list()
    with open(trace_file, 'r') as f:
        for log in f:
            log = log.strip()
            match = REPLAY_ACTION_PATTERN.match(log)
            if match:
                actions.append(parse_action(log, match))
                continue
            
            match = REPLAY_VIEW_INSTRUMENTATION_PATTERN.match(log)
            if match:
                instrument = parse_instrumentation(log, match)
                if instrument:
                    instrumentations.append(instrument)
                continue

            match = REPLAY_TIME_INTERVAL_PATTERN.match(log)
            if match:
                time_intervals.append(parse_time_interval(log, match))
                continue
    # Link instrumentation to actions
    for instrumentation in reversed(instrumentations):
        action_count = int(instrumentation['action_count'])
        for action in actions:
            if action['action_count'] == action_count:
                if 'instrumentation' not in action:
                    action['instrumentation'] = list()
                action['instrumentation'].append(instrumentation)
    # Link time_intervals to actions
    for ti in time_intervals:
        action_count = ti['action_count']
        _candidate = None
        _candidate_action_count = -1
        for action in actions:
            if action['action_count'] == action_count:
                action['time_interval'] = ti['interval']
                _candidate = None
                break
            if action['action_count'] < action_count and action['action_count'] > _candidate_action_count:
                _candidate = action
                _candidate_action_count = action['action_count']
        if _candidate is not None:
            _candidate['time_interval'] += ti['interval']
    pprint(actions)
    return actions


def get_view_hierarchy_component_bounds(component):
    """
    :param component, BeautifulSoup element
    """
    width, height = int(component['right']) - int(component['left']), int(component['bottom']) - int(component['top'])
    elements = list(component.parents)
    elements.reverse()
    elements.append(component)
    left, top = 0, 0
    for element in elements:
        if 'left' in element.attrs and len(element['left']) > 0:
            left += int(element['left'])
            top += int(element['top'])
    return get_bounds(left, top, left + width, top + height)


def find_best_match_candidate(candidates, x, y):
    best_match_candidate = None
    best_match_x_dis, best_match_y_dis = math.inf, math.inf
    for cc in candidates:
        left, top, right, bottom = cc['abs_left'], cc['abs_top'], cc['abs_right'], cc['abs_bottom']
        if left <= x <= right and top <= y <= bottom:
            # Matched
            x_dis = min(x - left, right - x)
            y_dis = min(y - top, bottom - y)
            if x_dis <= best_match_x_dis and y_dis <= best_match_y_dis:
                # best match
                best_match_candidate = cc
                best_match_x_dis = x_dis
                best_match_y_dis = y_dis
    return best_match_candidate


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


def find_component(ui_xml, bounds, rid):
    """
    Find components with bounds and resource-id
    """
    print(rid, bounds)
    components = ui_xml.findAll(attrs={
        'resource-id': rid
    })
    if len(components) == 0:
        # Resource id mismatch, then find with bounds
        components = ui_xml.findAll(attrs={
            'bounds': bounds
        })
    def _sort(x):
        if 'bounds' not in x.attrs:
            return -1
        return check_bounds_overlap(parse_bounds(x['bounds']), parse_bounds(bounds))
    components.sort(key=_sort, reverse=True)
    return components


def find_component_in_view_hierarchy(candidate, view_hierarchy):
    components = view_hierarchy.findAll(attrs={
        'resource_id': candidate['rid'],
        'classname': candidate['classname'],
        'view_id': candidate['vid'],
        'address': candidate['address'],
        'left': candidate['left'],
        'right': candidate['right'],
        'top': candidate['top'],
        'bottom': candidate['bottom']
    })
    if len(components) == 0:
        return None
    else:
        return components[0]


def uiautomator_dfs(tag, source_x, source_y, matched):
    """
    Find components in depth-first manner
    """
    bounds = tag['bounds']
    v_left, v_top, v_right, v_bottom = parse_bounds(bounds)
    is_visible = tag['visible-to-user'] == 'true'
    is_enable = tag['enabled'] == 'true'

    if is_visible and is_enable and v_left <= source_x <= v_right and v_top <= source_y <= v_bottom:
        children_feedback = list()
        for child in tag.children:
            if isinstance(child, bs4.element.Tag):
                children_feedback.append(uiautomator_dfs(child, source_x, source_y, matched))
        if list(children_feedback) == 0:
            # Leaf node
            matched.append(tag)
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
            matched.append(tag)
            return True
    else:
        return False


def xpath_soup(element, lxml_root):
    """
    Generate xpath from BeautifulSoup4 element
    :param element: BeautifulSoup4 element.
    :type element: bs4.element.Tag or bs4.element.NavigableString
    :return: xpath as string
    :rtype: str
    """
    components = []
    child = element
    xpath = None
    for parent in child.parents:
        """
        @type parent: bs4.element.Tag
        """
        if 'class' in child.attrs:
            siblings = parent.find_all(attrs={'text': child['text'], 'resource-id': child['resource-id'], 'package': child['package'], 'content-desc': child['content-desc']}, recursive=False)
            if len(siblings) > 0:
                components.append(
                    '%s[@text="%s" and @package="%s" and @resource-id="%s" and @content-desc="%s"]' % (child.name, child['text'].replace('"', '&quot;') if '"' in child['text'] else child['text'], child['package'], child['resource-id'], child['content-desc']) if siblings == [child] else 
                    '%s[@text="%s" and @package="%s" and @resource-id="%s" and @content-desc="%s"][%d]' % (child.name, child['text'].replace('"', '\\"') if '"' in child['text'] else child['text'], child['package'], child['resource-id'], child['content-desc'], 1 + siblings.index(child))
                )

                # Generalization
                xpath = '//%s' % '/'.join(list(reversed(components)))
                print(xpath)
                matched = lxml_root.xpath(xpath)
                if len(matched) == 1:
                    return xpath

            else:
                siblings = parent.find_all(child.name, recursive=False)
                components.append(
                    child.name
                    if siblings == [child] else
                    '%s[%d]' % (child.name, 1 + siblings.index(child))
                )
        else:
            siblings = parent.find_all(child.name, recursive=False)
            components.append(
                child.name
                if siblings == [child] else
                '%s[%d]' % (child.name, 1 + siblings.index(child))
            )
        child = parent

    components.reverse()
    xpath = '/%s' % '/'.join(components)
    prefix = '/html/body'
    assert xpath.startswith(prefix)
    return xpath[len(prefix):]


def xpath_view_hierarchy(element, lxml_view_hierarchy):
    """
    Generate xpath from BeautifulSoup4 element
    :param element: BeautifulSoup4 element.
    :type element: bs4.element.Tag or bs4.element.NavigableString
    :return: xpath as string
    :rtype: str
    """
    components = []
    child = element
    xpath = None
    for parent in child.parents:
        """
        @type parent: bs4.element.Tag
        """
        if 'resource_id' in child.attrs:
            siblings = parent.find_all(attrs={'resource_id': child['resource_id']}, recursive=False)
            if len(siblings) > 0:
                components.append(
                    '%s[@resource_id="%s"]' % (child.name, child['resource_id']) if siblings == [child] else 
                    '%s[@resource_id="%s"][%d]' % (child.name, child['resource_id'], 1 + siblings.index(child))
                )

                # Generalization
                xpath = '//%s' % '/'.join(list(reversed(components)))
                matched = lxml_view_hierarchy.xpath(xpath)
                if len(matched) == 1:
                    return xpath

            else:
                siblings = parent.find_all(child.name, recursive=False)
                components.append(
                    child.name
                    if siblings == [child] else
                    '%s[%d]' % (child.name, 1 + siblings.index(child))
                )
        else:
            siblings = parent.find_all(child.name, recursive=False)
            components.append(
                child.name
                if siblings == [child] else
                '%s[%d]' % (child.name, 1 + siblings.index(child))
            )
        child = parent

    components.reverse()
    xpath = '/%s' % '/'.join(components)
    prefix = '/html/body'
    assert xpath.startswith(prefix)
    return xpath[len(prefix):]


def get_first_scrollable(element):
    """
    Get the first scrollable element
    """
    for parent in element.parents:
        if 'scrollable' not in parent.attrs:
            return None
        if parent['scrollable'] == 'true':
            return parent
    return None


def get_first_scrollable_in_view_hierarchy(element):
    for parent in element.parents:
        if 'scroll_verti' not in parent.attrs:
            continue
        if parent['scroll_verti'] == 'true':
            return parent
    return None



def check_cudes(tag):
    if tag.has_attr('text') and tag.has_attr('resource-id') and tag.has_attr('content-desc'):
        text = tag['text']
        rid = tag['resource-id']
        description = tag['content-desc']
        if len(text) != 0 or len(rid) != 0 or len(description) != 0:
            return True
    return False


def generate_signature_from_children(matches, component):
    """
    Try to derive signature from the children of component
    """
    # Derive cudes from children
    target_idx = -1
    cudes = list()
    for idx, node in enumerate(matches):
        sub_components = node.findAll(check_cudes)
        _cudes = list()
        for sc in sub_components:
            _cudes.append({
                'text': sc['text'] if 'text' in sc.attrs else 'None',
                'content-desc': sc['content-desc'] if 'content-desc' in sc.attrs else 'None',
                'resource-id': sc['resource-id'] if 'resource-id' in sc.attrs else 'None',
                'class': sc['class'] if 'class' in sc.attrs else 'None',
            })
        cudes.append(_cudes)
        if node is component:
            target_idx = idx

    # Evaluate the effectiveness of each cude
    target_component_cudes = cudes[target_idx]
    del cudes[target_idx]
    for cude in cudes:
        to_be_remove = list()
        for tc in target_component_cudes:
            for c in cude:
                if tc['text'] == c['text'] and tc['class'] == c['class'] and tc['content-desc'] == c['content-desc'] and tc['resource-id'] == c['resource-id']:
                    to_be_remove.append(tc)
                    break
        for tc in to_be_remove:
            target_component_cudes.remove(tc)

    if len(target_component_cudes) == 0:
        return None
    return target_component_cudes[0]


def generate_signature_from_parent(matches, component):
    """
    Assume that all these matches in the same level of ui tree
    Lowest Common Ancestor
    """
    # Find lowest common ancestor
    target_idx = -1
    parents = list()
    for idx, node in enumerate(matches):
        parents.append(list(node.parents)[::-1])
        if node is component:
            target_idx = idx

    min_level = min([len(p) for p in parents])

    level = -1
    for level_idx in range(min_level):
        for p_idx in range(1, len(parents)):
            if parents[0][level_idx] is not parents[p_idx][level_idx]:
                level = level_idx
                break
        if level != -1:
            break
    else:
        # Not Found
        print('Lowest Common ancestor not found')
        return None

    # Enumerate cudes for finding component
    tags = [p[level] for p in parents]
    cudes = list()
    for tag in tags:
        sub_components = tag.findAll(check_cudes)
        _cudes = list()
        for sc in sub_components:
            _cudes.append({
                'text': sc['text'] if 'text' in sc.attrs else 'None',
                'content-desc': sc['content-desc'] if 'content-desc' in sc.attrs else 'None',
                'resource-id': sc['resource-id'] if 'resource-id' in sc.attrs else 'None',
                'class': sc['class'] if 'class' in sc.attrs else 'None',
            })
        cudes.append(_cudes)

    # Evaluate the effectiveness of each cude
    target_component_cudes = cudes[target_idx]
    del cudes[target_idx]
    for cude in cudes:
        to_be_remove = list()
        for tc in target_component_cudes:
            for c in cude:
                if tc['text'] == c['text'] and tc['class'] == c['class'] and tc['content-desc'] == c['content-desc'] and tc['resource-id'] == c['resource-id']:
                    to_be_remove.append(tc)
                    break
        for tc in to_be_remove:
            target_component_cudes.remove(tc)

    if len(target_component_cudes) == 0:
        return None
    return target_component_cudes[0]


def generate_signature(component, scrollable_view):
    own_signature = {
        'class': component['class'],
        'resource-id': component['resource-id'],
        'text': component['text'],
        'content-desc': component['content-desc']
    }
    matches = scrollable_view.findAll(attrs=own_signature)

    assert len(matches) > 0

    if len(matches) == 1:
        print('Only one match! Yeah ~~')
        return ('Own', own_signature)
    
    # Multiple matches
    valid_children = list()
    for child in component.children:
        if isinstance(child, bs4.element.Tag):
            valid_children.append(child)
    
    if len(valid_children) > 0:
        # Try to generate signature from its children
        signature = generate_signature_from_children(matches, component)
        if signature is not None:
            # Path from children to component
            return ('Children', own_signature, signature)
    signature = generate_signature_from_parent(matches, component)
    if signature is None:
        return None
    # Path from parent to compoent
    return ('Parent', own_signature, signature)


def transform_click(action_info, ui_xml, lxml_root, view_hierarchy, lxml_view_hierarchy):
    print(action_info)
    package_name = action_info['package']
    view_type = action_info['info']['view_type']
    click_x, click_y = action_info['info']['x'], action_info['info']['y']
    should_find_signature = True
    if view_type == 'Activity' and len(action_info['info']['candidate']) > 0:
        # Get candidate
        candidates = action_info['info']['candidate']
        if 'instrumentation' not in action_info:
            should_find_signature = False
        if isinstance(candidates, list):
            candidate = None
            if 'instrumentation' not in action_info:
                # Find closest
                candidate = find_best_match_candidate(candidates, click_x, click_y)
            else:
                instrumentations = action_info['instrumentation']
                matched_candidates = list()
                for instru in instrumentations:
                    view = instru['view']
                    for can in candidates:
                        if can['address'] in view:
                            matched_candidates.append(can)
                if len(matched_candidates) > 0:
                    # Assign higher priority to those candidates that have resource-id
                    for can in matched_candidates:
                        if len(can['rid']) > 0 and len(can['vid']) > 0:
                            candidate = can
                            break
                    else:
                        candidate = matched_candidates[0]
                else:
                    # Find the first in view hierarchy
                    def _sort(x):
                        view = parse_view(x['view'])
                        if view is None:
                            return math.inf
                        left, top, right, bottom = int(view['left']), int(view['top']), int(view['right']), int(view['bottom'])
                        return abs(right - left) * abs(bottom - top)
                    instrumentations.sort(key=_sort)
                    print(instrumentations)
                    for instru in instrumentations:
                        view = parse_view(instru['view'])
                        if view is None:
                            continue
                        candidate = find_component_in_view_hierarchy({
                            'rid': view['resource_id'],
                            'classname': view['classname'],
                            'vid': view['view_id'],
                            'address': view['address'],
                            'left': view['left'],
                            'right': view['right'],
                            'top': view['top'],
                            'bottom': view['bottom']
                        }, view_hierarchy)
                        if candidate:
                            bounds = get_view_hierarchy_component_bounds(candidate)
                            abs_left, abs_top, abs_right, abs_bottom = parse_bounds(bounds)
                            candidate = {
                                'rid': candidate['resource_id'],
                                'vid': candidate['view_id'],
                                'classname': candidate['classname'],
                                'address': candidate['address'],
                                'left': int(candidate['left']),
                                'top': int(candidate['top']),
                                'right': int(candidate['right']),
                                'bottom': int(candidate['bottom']),
                                'is_visible': candidate['visible'] == 'true',
                                'is_enable': candidate['enabled'] == 'true',
                                'is_clickable': candidate['clickable'] == 'true',
                                'abs_left': abs_left,
                                'abs_top': abs_top,
                                'abs_right': abs_right,
                                'abs_bottom': abs_bottom,
                                'scroll_horiz': candidate['scroll_horiz'] == 'true',
                                'scroll_verti': candidate['scroll_verti'] == 'true',
                            }
                            break
                    if candidate is None:
                        candidate = find_best_match_candidate(candidates, click_x, click_y)
        else:
            candidate = candidates
        print('Candidate: ', candidate)
        assert not isinstance(candidate, list)
        
        # Get component corresponds to the candidate 
        view_hierarchy_component = find_component_in_view_hierarchy(candidate, view_hierarchy)
        bounds = get_bounds(candidate['abs_left'], candidate['abs_top'], candidate['abs_right'], candidate['abs_bottom'])
        rid = replace_package_name(candidate['rid'], package_name)
        components = find_component(ui_xml, bounds, rid)
        print('# Components: ', len(components))
        component = None
        if len(components) > 0:
            for com in components:
                cleft, ctop, cright, cbottom = parse_bounds(com['bounds'])
                if cleft <= click_x <= cright and ctop <= click_y <= cbottom:
                    component = com
                    break
        if component is None or len(components) == 0:
            # Fail to find component in ui xml, then find it in view hierarchy
            print('View hierarchy component: ', view_hierarchy_component)
            xpath = xpath_view_hierarchy(view_hierarchy_component, lxml_view_hierarchy)
            cleft, ctop, cright, cbottom = candidate['abs_left'], candidate['abs_top'], candidate['abs_right'], candidate['abs_bottom']
            if cleft <= click_x <= cright and ctop <= click_y <= cbottom:
                x_offset_dp, y_offset_dp = px2dp(click_x - cleft, source_dpi), px2dp(click_y - ctop, source_dpi)
            else:
                # absolute position may be incorrect
                transformed_x, transformed_y = transform_coordinate(click_x, click_y)
                return 'perform_click_event_with_raw_coordinate("%s", %f, %f, %f)' % (action_info['info']['tap_type'], transformed_x, transformed_y, action_info['info']['duration'])
            # assert cleft <= click_x <= cright and ctop <= click_y <= cbottom
            # x_offset_dp, y_offset_dp = px2dp(click_x - cleft, source_dpi), px2dp(click_y - ctop, source_dpi)
            return 'perform_click_event_with_view_hierarchy("""%s""", "%s", %f, %f, %f, %d)' % (xpath, action_info['info']['tap_type'], x_offset_dp, y_offset_dp, action_info['info']['duration'], target_dpi)

        scrollable_element = get_first_scrollable(component)
        if scrollable_element is None:
            scrollable_element_in_view_hierarchy = get_first_scrollable_in_view_hierarchy(view_hierarchy_component)
            if scrollable_element_in_view_hierarchy is not None:
                bounds = get_view_hierarchy_component_bounds(scrollable_element_in_view_hierarchy)
                rid = replace_package_name(scrollable_element_in_view_hierarchy['resource_id'], package_name)
                scrollable_elements = find_component(ui_xml, bounds, rid)
                print('# Scrollable Components: ', len(scrollable_elements))
                if len(scrollable_elements) > 0:
                    scrollable_element = scrollable_elements[0]
                    # assert len(scrollable_elements) > 0
                else:
                    scrollable_element = None
    else:
        # PopupWindow & Dialog
        # Find closest component
        root = ui_xml.find('hierarchy')
        matched_nodes = list()
        for child in root.children:
            if isinstance(child, bs4.element.Tag):
                uiautomator_dfs(child, click_x, click_y, matched_nodes)
        if len(matched_nodes) == 0:
            # No component, then just simply translate coordinate
            transformed_x, transformed_y = transform_coordinate(click_x, click_y)
            return 'perform_click_event_with_raw_coordinate("%s", %f, %f, %f)' % (action_info['info']['tap_type'], transformed_x, transformed_y, action_info['info']['duration'])
        print('Dialog || Popup Window: ')
        print(matched_nodes)
        def _sort(x):
            left, top, right, bottom = parse_bounds(x['bounds'])
            return abs(right - left) * abs(bottom - top)
        matched_nodes.sort(key=_sort)
        # Order by distance
        component = matched_nodes[0]

        should_find_signature = False
        scrollable_element = get_first_scrollable(component)
        if scrollable_element is not None:
            should_find_signature = True

    cleft, ctop, cright, cbottom = parse_bounds(component['bounds'])
    x_offset_dp, y_offset_dp = px2dp(click_x - cleft, source_dpi), px2dp(click_y - ctop, source_dpi)

    # Generate xpath
    if should_find_signature and scrollable_element:
        signature = generate_signature(component, scrollable_element)
        print('Signature: ', signature)
        if signature is None:
            print('Fail to find signature for component')
            x_path = xpath_soup(component, lxml_root)
            return 'perform_click_event_with_xpath("""%s""", "%s", %f, %f, %f, %d)' % (x_path, action_info['info']['tap_type'], x_offset_dp, y_offset_dp, action_info['info']['duration'], target_dpi)
        else:
            print(signature)
            sig_type = signature[0]
            own_signature = signature[1]
            scrollable_element_xpath = xpath_soup(scrollable_element, lxml_root)
            if sig_type == 'Own':
                return 'perform_click_event_with_u2_own_signature("""%s""", %s, "%s", %f, %f, %f, %d)' % (scrollable_element_xpath, json.dumps(own_signature), action_info['info']['tap_type'], x_offset_dp, y_offset_dp, action_info['info']['duration'], target_dpi)
            elif sig_type == 'Children':
                # Children
                child_signature = signature[2]
                return 'perform_clcik_event_with_u2_child_signature("""%s""", %s, %s, "%s", %f, %f, %f, %d)' % (scrollable_element_xpath, json.dumps(own_signature), json.dumps(child_signature), action_info['info']['tap_type'], x_offset_dp, y_offset_dp, action_info['info']['duration'], target_dpi)
            else:
                # Parent
                parent_signature = signature[2]
                return 'perform_click_event_with_u2_parent_signature("""%s""", %s, %s, "%s", %f, %f, %f, %d)' % (scrollable_element_xpath, json.dumps(own_signature), json.dumps(parent_signature), action_info['info']['tap_type'], x_offset_dp, y_offset_dp, action_info['info']['duration'], target_dpi)
    else:
        x_path = xpath_soup(component, lxml_root)
        return 'perform_click_event_with_xpath("""%s""", "%s", %f, %f, %f, %d)' % (x_path, action_info['info']['tap_type'], x_offset_dp, y_offset_dp, action_info['info']['duration'], target_dpi)


def transform_swipe(points):

    if target_width == source_width and target_height == source_height and target_dpi == source_dpi:
        return points

    transformed_points = list()
    for point in points:
        new_x, new_y = transform_coordinate(point[0], point[1])
        transformed_points.append([new_x, new_y])
    # Get direction, vertical or horizonal 
    max_distance_x = 0
    max_distance_y = 0
    begin_x, begin_y = transformed_points[0][0], transformed_points[0][1]
    for point in transformed_points[1:]:
        curr_distance_x = abs(point[0] - begin_x)
        curr_distance_y = abs(point[1] - begin_y)
        max_distance_x = max(max_distance_x, curr_distance_x)
        max_distance_y = max(max_distance_y, curr_distance_y)
    
    if begin_x + max_distance_x <= target_width and begin_y + max_distance_y <= target_height:
        return transformed_points

    # Tune the points since they overflows

    if begin_y + max_distance_y > target_height:
        # Transition
        max_delta = 0
        for point in transformed_points:
            y = point[1]
            if y > target_height and y - target_height > max_delta:
                max_delta = y - target_height
        for point in transformed_points:
            point[1] = max(1, point[1] - max_delta - 10)

    if begin_x + max_distance_x > target_width:
        # Simply drop those overflowed points
        point_to_remove = list()
        for point in transformed_points:
            x = point[0]
            if x > target_width:
                point_to_remove.append(point)
        for p in point_to_remove:
            transformed_points.remove(p)
    return transformed_points


def init_script():
    code = """# coding=utf8

import os
import sys
import time
import json
import frida
import argparse
import uiautomator2 as u2
from script import util

xml = None
lxml = None
view_hierarchy = None
lxml_view_hierarchy = None
save_path = None
action_count = 0
sub_action_count = 0
current_popup_window = None
curr_webview_address = None

display_width = None
display_height = None

samsung = False
sessions = None

def log(desc):
    global action_count
    print('[WidgetReplayAction]-%d: ' % action_count, desc)


def preprocess_path():
    global save_path
    if save_path is None:
        return False
    if not os.path.exists(save_path):
        os.mkdir(save_path)
    else:
        for file in os.listdir(save_path):
            os.remove(os.path.join(save_path, file))
    return True


def error_handler(func):
    def wrapper(message, data):
        if message['type'] == 'error':
            print('[Func]: %s, [Error-msg]: %s' % (func.__name__, message))
            print('[Func]: %s, [Error-des]: %s' % (func.__name__, message['description']))
            print('[Func]: %s, [Error-sta]: %s' % (func.__name__, message['stack']))
            print('[Func]: %s, [Error-dat]: %s' % (func.__name__, data))
            return None
        else:
            return func(message, data)
    return wrapper


def post_action(custom_interval):
    global xml
    global lxml_xml
    global d
    global action_count
    global save_path
    global view_hierarchy
    global lxml_view_hierarchy
    global sub_action_count

    print('[WidgetReplayTimeInterval]-%d: %s' % (action_count, json.dumps({'interval': custom_interval})))
    if action_count > 0:
        # time.sleep(1)
        if custom_interval > 0:
            time.sleep(custom_interval)
    xml = d.dump_hierarchy()
    lxml_xml = util.parse_lxml_xml(xml)
    xml = util.parse_xml(xml)
    screenshot_filename = os.path.join(save_path, '_'.join(['screenshot', str(action_count)]) + '.jpg')
    xml_filename = os.path.join(save_path, '_'.join(['ui', str(action_count)]) + '.xml')
    view_hierarchy_filename = os.path.join(save_path, '_'.join(['view_hierarchy', str(action_count)]) + '.xml')
    d.screenshot(screenshot_filename)
    util.save_xml(xml, xml_filename)
    view_hierarchy, lxml_view_hierarchy = util.dump_view_hierarchy(d, view_hierarchy_filename)
    action_count += 1
    sub_action_count = 0


def update_dump():
    global xml
    global lxml_xml
    global d
    global action_count
    global save_path
    global view_hierarchy
    global lxml_view_hierarchy
    global sub_action_count

    xml = d.dump_hierarchy()
    lxml_xml = util.parse_lxml_xml(xml)
    xml = util.parse_xml(xml)
    screenshot_filename = os.path.join(save_path, '_'.join(['screenshot', str(action_count), str(sub_action_count)]) + '.jpg')
    xml_filename = os.path.join(save_path, '_'.join(['ui', str(action_count), str(sub_action_count)]) + '.xml')
    view_hierarchy_filename = os.path.join(save_path, '_'.join(['view_hierarchy', str(action_count), str(sub_action_count)]) + '.xml')
    d.screenshot(screenshot_filename)
    util.save_xml(xml, xml_filename)
    view_hierarchy, lxml_view_hierarchy = util.dump_view_hierarchy(d, view_hierarchy_filename)
    sub_action_count += 1

def set_text(text, package_name):
    global xml
    focused = d(focused=True)
    if focused.count > 0:
        if focused.info['packageName'] != package_name:
            d.shell('input text "%s"' % text)
        else:
            focused.set_text(text)
    else:
        d.shell('input text "%s"' % text)
    log('[set_text]-%s' % json.dumps({'text': text}))


def press_soft_keyboard(key_name):
    global xml
    index = util.find_soft_key(key_name, xml, is_samsung)
    if index is None:
        raise Exception('Key ' + key_name + ' does not exist')
    key_x, key_y = index[0], index[1]
    d.click(key_x, key_y)
    log('[press_key]-%s' % json.dumps({'key_name': key_name}))


def hide_soft_keyboard():
    global xml
    if util.check_soft_keyboard(xml):
        print('Hide soft keyboard')
        d.press('back')
        log('[hide_keyboard]')


def record_popup_window():
    global current_popup_window
    current_popup_window = util.get_current_window(d)
    log('[record_popup_window]-%s' % json.dumps({'window': current_popup_window}))


def close_popup_window():
    global current_popup_window
    if current_popup_window is not None:
        window = util.get_current_window(d)
        if window == current_popup_window:
            d.press('back')
            log('[hide_popup_window]-%s' % json.dumps({'window': current_popup_window}))
            current_popup_window = None


def perform_click_event_with_xpath(xpath, tap_type, x_offset, y_offset, duration, target_dpi):
    global lxml_xml

    component = lxml_xml.xpath(xpath)
    assert len(component) > 0
    component = component[0]

    x, y = util.get_target_coordinate(component.attrib['bounds'], x_offset, y_offset, target_dpi)

    # log('[click]-%s' % json.dumps({
    #     'tap_type': tap_type,
    #     'x': x,
    #     'y': y,
    #     'duration': duration,
    #     'component': {
    #         'class': component.attrib['class'] if 'class' in component.attrib else '',
    #         'rid': component.attrib['resource-id'] if 'resource-id' in component.attrib else '',
    #         'bounds': component.attrib['bounds'] if 'bounds' in component.attrib else '',
    #         'text': component.attrib['text'] if 'text' in component.attrib else '',
    #         'desc': component.attrib['content-desc'] if 'content-desc' in component.attrib else '',
    #     }
    # }))

    if tap_type == 'LongTap':
        d.long_click(x, y, duration)
    elif tap_type == 'Tap':
        d.long_click(x, y, duration)
    elif tap_type == 'DoubleTap':
        d.double_click(x, y, 0.1)


def perform_click_event_with_u2_own_signature(scrollable_xpath, component_signature, tap_type, x_offset, y_offset, duration, target_dpi):
    global lxml_xml

    scrollable = lxml_xml.xpath(scrollable_xpath)
    assert len(scrollable) == 1
    scrollable = scrollable[0]

    scroll_attrs = {
        'resourceId': scrollable.attrib['resource-id'],
        'className': scrollable.attrib['class'],
        'packageName': scrollable.attrib['package'],
        'text': scrollable.attrib['text'],
        'description': scrollable.attrib['content-desc']
    }

    for k in list(scroll_attrs.keys()):
        if len(scroll_attrs[k]) == 0:
            del scroll_attrs[k]

    child_func_attrs = {
        'className': component_signature['class'][0],
        'resourceId': component_signature['resource-id']
    }
    if len(child_func_attrs['resourceId']) == 0:
        del child_func_attrs['resourceId']

    scrollable_u2_element = d(**scroll_attrs)
    if scrollable_u2_element.count > 0:
        left, top, right, bottom = util.parse_bounds(scrollable.attrib['bounds'])
        for i in range(scrollable_u2_element.count):
            if scrollable_u2_element[i].info['bounds']['left'] == left and scrollable_u2_element[i].info['bounds']['right'] == right and scrollable_u2_element[i].info['bounds']['top'] == top and scrollable_u2_element[i].info['bounds']['bottom'] == bottom:
                scrollable_u2_element = scrollable_u2_element[i]

    if len(component_signature['text']) == 0 and len(component_signature['content-desc']) == 0:
        element = scrollable_u2_element.child(**child_func_attrs)
        if not element.exists:
            scrollable_u2_element.scroll(steps=100)
            element = scrollable_u2_element.child(**child_func_attrs)
    elif len(component_signature['text']) > 0:
        child_func_attrs['txt'] = component_signature['text']
        child_func_attrs['allow_scroll_search'] = True
        element = scrollable_u2_element.child_by_text(**child_func_attrs)
    else:
        child_func_attrs['txt'] = component_signature['content-desc']
        child_func_attrs['allow_scroll_search'] = True
        element = scrollable_u2_element.child_by_description(**child_func_attrs)
        element = d(description=component_signature['content-desc'])

    update_dump()

    # Element is an instance of UIObject
    bounds = element.info['bounds']
    x, y = util.get_target_coordinate(bounds, x_offset, y_offset, target_dpi)

    # log('[click]-%s' % json.dumps({
    #     'tap_type': tap_type,
    #     'x': x,
    #     'y': y,
    #     'duration': duration,
    #     'component': {
    #         'class': element.info['className'] if 'className' in element.info else '',
    #         'rid': element.info['resource-id'] if 'resource-id' in element.info else '',
    #         'bounds': element.info['bounds'] if 'bounds' in element.info else '',
    #         'text': element.info['text'] if 'text' in element.info else '',
    #         'desc': element.info['contentDescription'] if 'contentDescription' in element.info else '',
    #     }
    # }))

    if tap_type == 'LongTap':
        d.long_click(x, y, duration)
    elif tap_type == 'Tap':
        d.long_click(x, y, duration)
    elif tap_type == 'DoubleTap':
        d.double_click(x, y, 0.1)


def perform_click_event_with_u2_parent_signature(scrollable_xpath, component_signature, parent_signature, tap_type, x_offset, y_offset, duration, target_dpi):
    global lxml_xml

    scrollable = lxml_xml.xpath(scrollable_xpath)
    assert len(scrollable) == 1
    scrollable = scrollable[0]

    scroll_attrs = {
        'resourceId': scrollable.attrib['resource-id'],
        'className': scrollable.attrib['class'],
        'packageName': scrollable.attrib['package'],
        'text': scrollable.attrib['text'],
        'description': scrollable.attrib['content-desc']
    }

    for k in list(scroll_attrs.keys()):
        if len(scroll_attrs[k]) == 0:
            del scroll_attrs[k]

    # Find parent
    child_func_attrs = {
        'className': parent_signature['class'][0],
        'resourceId': parent_signature['resource-id']
    }
    if len(child_func_attrs['resourceId']) == 0:
        del child_func_attrs['resourceId']

    scrollable_u2_element = d(**scroll_attrs)
    if scrollable_u2_element.count > 0:
        left, top, right, bottom = util.parse_bounds(scrollable.attrib['bounds'])
        print(left, top, right, bottom)
        for i in range(scrollable_u2_element.count):
            print(scrollable_u2_element[i].info['bounds'])
            if scrollable_u2_element[i].info['bounds']['left'] == left and scrollable_u2_element[i].info['bounds']['right'] == right and scrollable_u2_element[i].info['bounds']['top'] == top and scrollable_u2_element[i].info['bounds']['bottom'] == bottom:
                scrollable_u2_element = scrollable_u2_element[i]
                break

    if len(parent_signature['text']) == 0 and len(parent_signature['content-desc']) == 0:
        element = scrollable_u2_element.child(**child_func_attrs)
        if not element.exists:
            scrollable_u2_element.scroll(steps=100)
            element = scrollable_u2_element.child(**child_func_attrs)
    elif len(parent_signature['text']) > 0:
        child_func_attrs['txt'] = parent_signature['text']
        child_func_attrs['allow_scroll_search'] = True
        element = scrollable_u2_element.child_by_text(**child_func_attrs)
    else:
        child_func_attrs['txt'] = parent_signature['content-desc']
        child_func_attrs['allow_scroll_search'] = True
        element = scrollable_u2_element.child_by_description(**child_func_attrs)
        element = d(description=component_signature['content-desc'])


    update_dump()

    bounds = util.get_bounds(element.info['bounds']['left'], element.info['bounds']['top'], element.info['bounds']['right'], element.info['bounds']['bottom'])

    # Find target in xml
    component = util.find_target_component(xml, component_signature, {
        'bounds': bounds,
        'class': element.info['className'],
        'package': element.info['packageName'],
        'resource-id': parent_signature['resource-id'],
        'content-desc': parent_signature['content-desc'],
        'text': parent_signature['text']
    })

    # component is an instance of bs4.element.Tag
    x, y = util.get_target_coordinate(component.attrs['bounds'], x_offset, y_offset, target_dpi)

    # log('[click]-%s' % json.dumps({
    #     'tap_type': tap_type,
    #     'x': x,
    #     'y': y,
    #     'duration': duration,
    #     'component': {
    #         'class': component.attrs['class'] if 'class' in component.attrs else '',
    #         'rid': component.attrs['resource-id'] if 'resource-id' in component.attrs else '',
    #         'bounds': component.attrs['bounds'] if 'bounds' in component.attrs else '',
    #         'text': component.attrs['text'] if 'text' in component.attrs else '',
    #         'desc': component.attrs['content-desc'] if 'content-desc' in component.attrs else '',
    #     }
    # }))

    if tap_type == 'LongTap':
        d.long_click(x, y, duration)
    elif tap_type == 'Tap':
        d.long_click(x, y, duration)
    elif tap_type == 'DoubleTap':
        d.double_click(x, y, 0.1)


def perform_clcik_event_with_u2_child_signature(scrollable_xpath, component_signature, child_signature, tap_type, x_offset, y_offset, duration, target_dpi):
    global lxml_xml
    global xml

    scrollable = lxml_xml.xpath(scrollable_xpath)
    assert len(scrollable) == 1
    scrollable = scrollable[0]

    scroll_attrs = {
        'resourceId': scrollable.attrib['resource-id'],
        'className': scrollable.attrib['class'],
        'packageName': scrollable.attrib['package'],
        'text': scrollable.attrib['text'],
        'description': scrollable.attrib['content-desc']
    }

    for k in list(scroll_attrs.keys()):
        if len(scroll_attrs[k]) == 0:
            del scroll_attrs[k]

    # Find Child
    child_func_attrs = {
        'className': child_signature['class'][0],
        'resourceId': child_signature['resource-id']
    }
    if len(child_func_attrs['resourceId']) == 0:
        del child_func_attrs['resourceId']
    
    scrollable_u2_element = d(**scroll_attrs)
    if scrollable_u2_element.count > 0:
        left, top, right, bottom = util.parse_bounds(scrollable.attrib['bounds'])
        for i in range(scrollable_u2_element.count):
            if scrollable_u2_element[i].info['bounds']['left'] == left and scrollable_u2_element[i].info['bounds']['right'] == right and scrollable_u2_element[i].info['bounds']['top'] == top and scrollable_u2_element[i].info['bounds']['bottom'] == bottom:
                scrollable_u2_element = scrollable_u2_element[i]

    if len(child_signature['text']) == 0 and len(child_signature['content-desc']) == 0:
        element = scrollable_u2_element.child(**child_func_attrs)
        if not element.exists:
            scrollable_u2_element.scroll(steps=100)
            element = scrollable_u2_element.child(**child_func_attrs)
    elif len(child_signature['text']) > 0:
        child_func_attrs['txt'] = child_signature['text']
        child_func_attrs['allow_scroll_search'] = True
        element = scrollable_u2_element.child_by_text(**child_func_attrs)
    else:
        child_func_attrs['txt'] = child_signature['content-desc']
        child_func_attrs['allow_scroll_search'] = True
        element = scrollable_u2_element.child_by_description(**child_func_attrs)
        element = d(description=component_signature['content-desc'])

    update_dump()

    bounds = util.get_bounds(element.info['bounds']['left'], element.info['bounds']['top'], element.info['bounds']['right'], element.info['bounds']['bottom'])
    # Find target in xml
    component = util.find_target_component(xml, component_signature, {
        'bounds': bounds,
        'class': element.info['className'],
        'package': element.info['packageName'],
        'resource-id': child_signature['resource-id'],
        'content-desc': child_signature['content-desc'],
        'text': child_signature['text']
    })

    # component is an instance of bs4.element.Tag
    x, y = util.get_target_coordinate(component['bounds'], x_offset, y_offset, target_dpi)

    # log('[click]-%s' % json.dumps({
    #     'tap_type': tap_type,
    #     'x': x,
    #     'y': y,
    #     'duration': duration,
    #     'component': {
    #         'class': component['class'] if 'class' in component.attrs else '',
    #         'rid': component['resource-id'] if 'resource-id' in component.attrs else '',
    #         'bounds': component['bounds'] if 'bounds' in component.attrs else '',
    #         'text': component['text'] if 'text' in component.attrs else '',
    #         'desc': component['content-desc'] if 'content-desc' in component.attrs else '',
    #     }
    # }))

    if tap_type == 'LongTap':
        d.long_click(x, y, duration)
    elif tap_type == 'Tap':
        d.long_click(x, y, duration)
    elif tap_type == 'DoubleTap':
        d.double_click(x, y, 0.1)


def perform_click_event_with_view_hierarchy(xpath, tap_type, x_offset, y_offset, duration, target_dpi):
    global lxml_view_hierarchy

    component = lxml_view_hierarchy.xpath(xpath)
    assert len(component) == 1
    component = component[0]

    bounds = util.get_view_hierarchy_component_bounds(component)
    x, y = util.get_target_coordinate(bounds, x_offset, y_offset, target_dpi)

    # log('[click]-%s' % json.dumps({
    #     'tap_type': tap_type,
    #     'x': x,
    #     'y': y,
    #     'duration': duration,
    #     'component': {
    #         'class': component.attrib['classname'] if 'classname' in component.attrib else '',
    #         'rid': component.attrib['resource_id'] if 'resource_id' in component.attrib else '',
    #         'bounds': bounds,
    #         'text': '',
    #         'desc': '',
    #     }
    # }))

    if tap_type == 'LongTap':
        d.long_click(x, y, duration)
    elif tap_type == 'Tap':
        d.long_click(x, y, duration)
    elif tap_type == 'DoubleTap':
        d.double_click(x, y, 0.1)


def perform_click_event_with_raw_coordinate(tap_type, x, y, duration):
    # log('[click]-%s' % json.dumps({
    #     'tap_type': tap_type,
    #     'x': x,
    #     'y': y,
    #     'duration': duration,
    #     'component': {}
    # }))
    if tap_type == 'LongTap':
        d.long_click(x, y, duration)
    elif tap_type == 'Tap':
        d.long_click(x, y, duration)
    elif tap_type == 'DoubleTap':
        d.double_click(x, y, 0.1)


def perform_swipe_event(pointers, duration=0.01):
    d.swipe_points(pointers, 0.01)
    # log('[swipe]-%s' % json.dumps({'pointers': pointers, 'duration': duration}))


def perform_key_event(key_code):
    d.press(key_code)
    # log('[press]-%s' % json.dumps({'key_code': key_code}))


def webview_set_text_with_u2(text):
    d(focused=True).set_text(text)
    # log('[webview_set_text]-%s' % json.dumps({'text': text}))


def instrument_low_level_sensor(session, listener_classname_dict):
    code = util.instrument_low_level_sensors(listener_classname_dict)
    script = session.create_script(code)
    script.on('message', get_instrument_low_level_sensor_message)
    script.load()


@error_handler
def get_instrument_low_level_sensor_message(message, data):
    msg = '[onSensorChanged]-%s' % json.dumps(message)
    print(msg)


def instrument_getlastknownlocation(session, get_location_classname_dict):
    code = util.instrument_getlastknownlocation(get_location_classname_dict)
    script = session.create_script(code)
    script.on('message', get_instrument_getlastknownlocation)
    script.load()


@error_handler
def get_instrument_getlastknownlocation(message, data):
    msg = '[getLastKnownLocation]-%s' % json.dumps(message)
    print(msg)


def instrument_onlocationchanged(session, on_location_classname_dict):
    code = util.instrument_onlocationchanged(on_location_classname_dict)
    script = session.create_script(code)
    script.on('message', get_instrument_onlocationchanged)
    script.load()


@error_handler
def get_instrument_onlocationchanged(message, data):
    msg = '[onLocationChanged]-%s' % json.dumps(message)
    print(msg)


def clean_up():
    global sessions
    print('Clean Up....')
    if sessions is not None:
        for session in sessions:
            session.detach()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--path', help='save path', required=True)
    parser.add_argument('--pids', nargs='+', help='list of pid', required=True)
    parser.add_argument('--serial', help='device serial, checked by `adb devices`', required=False)
    parser.set_defaults(samsung=False)
    parser.add_argument("--samsung", help="Is samsung ?", action="store_true")
    args = parser.parse_args()

    pids = [int(p) for p in args.pids]

    save_path = args.path
    if args.serial:
        d = u2.connect_usb(args.serial)
    else:
        d = u2.connect()
    print(d.info)

    display_width = d.info['displayWidth']
    display_height = d.info['displayHeight']

    is_samsung = args.samsung

    if not preprocess_path():
        print('Save path not found')
        sys.exit()

    post_action(0)
"""
    return [code]


def append_script(action, script, time_interval=None):
    script.append('    ' + action)
    if time_interval is None:
        script.append('    post_action(%f)' % 0.0)
    else:
        ti = float(time_interval) / 2
        script.append('    post_action(%f)' % ti)


def instrument_script():
    return """
    all_devices = frida.enumerate_devices()
    if args.serial:
        print('Serial: ', args.serial)
        device = frida.get_usb_device(args.serial)
    else:
        device = frida.get_usb_device()
    sessions = [device.attach(pid) for pid in pids]
    """


def append_end_snippet(script):
    script.append("""
    clean_up()
    """)


def transform_action(actions, log_dir, sensor_events):

    script = init_script()
    if len(sensor_events):
        script.append(instrument_script())
    
    if 'low_level_sensor' in sensor_events:
        for idx, listener_classname_dict in enumerate(sensor_events['low_level_sensor']):
            append_script('instrument_low_level_sensor(sessions[%d], %s)' % (idx, json.dumps(listener_classname_dict)), script)

    if 'get_location_events' in sensor_events:
        for idx, get_location_classname_dict in enumerate(sensor_events['get_location_events']):
            append_script('instrument_getlastknownlocation(sessions[%d], %s)' % (idx, json.dumps(get_location_classname_dict)), script)

    if 'on_location_events' in sensor_events:
        for idx, on_location_classname_dict in enumerate(sensor_events['on_location_events']):
            append_script('instrument_onlocationchanged(sessions[%d], %s)' % (idx, json.dumps(on_location_classname_dict)), script)

    for aidx, action in enumerate(actions):
        action_count = action['action_count']
        action_type = action['action']
        ui_xml = read_ui_xml(os.path.join(log_dir, 'ui_%d.xml' % (action_count-1)))
        lxml_root = lxml_read_ui_xml(os.path.join(log_dir, 'ui_%d.xml' % (action_count-1)))
        view_hierarchy = read_ui_xml(os.path.join(log_dir, 'view_hierarchy_%d.xml' % (action_count - 1)))
        lxml_view_hierarchy = lxml_read_ui_xml(os.path.join(log_dir, 'view_hierarchy_%d.xml' % (action_count - 1)))
        if action_type == 'click':
            click_action = transform_click(action, ui_xml, lxml_root, view_hierarchy, lxml_view_hierarchy)
            if click_action is None:
                continue
            append_script(click_action, script, action['time_interval'])
        elif action_type == 'swipe':
            points = action['info']['pointers']
            transformed_points = transform_swipe(points)
            new_swipe = 'perform_swipe_event(%s, %f)' % (str(transformed_points), action['info']['duration'])
            append_script(new_swipe, script, action['time_interval'])
        elif action_type == 'set_text':
            new_set_text = 'set_text("%s", "%s")' % (action['info']['text'], action['package'])
            append_script(new_set_text, script, action['time_interval'])
        elif action_type == 'press_key':
            # Soft key
            new_press_key = 'press_soft_keyboard("%s")' % action['info']['key_name']
            append_script(new_press_key, script, action['time_interval'])
        elif action_type == 'webview_set_text':
            new_webview_set_text = 'webview_set_text_with_u2(%s)' % action['info']['text']
            append_script(new_webview_set_text, script, action['time_interval'])
        elif action_type == 'press':
            # Physical key
            new_press = 'perform_key_event(%s)' % str(action['info']['key_code'])
            append_script(new_press, script, action['time_interval'])
        elif action_type == 'record_popup_window':
            append_script('record_popup_window()', script, action['time_interval'])
        elif action_type == 'hide_popup_window':
            append_script('close_popup_window()', script, action['time_interval'])

    append_end_snippet(script)
    replay_script = '\n'.join(script)
    return replay_script


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Argument Parser')
    parser.add_argument('--logdir', help='screenshot and xml save dir', required=True)
    parser.add_argument('--trace', help='trace recorded from replay', required=True)
    parser.add_argument('--sensor', help='sensor events', required=True)
    parser.add_argument('--sdevice', help='record device resolution: width,height,dpi', required=True)
    parser.add_argument('--tdevice', help='target device resolution: width,height,dpi', required=True)
    args = parser.parse_args()

    log_dir = args.logdir
    trace_file = args.trace
    sensor_events_file = args.sensor
    with open(sensor_events_file, 'r') as f:
        sensor_events = json.load(f)

    source_width, source_height, source_dpi = parse_resolution(args.sdevice)
    target_width, target_height, target_dpi = parse_resolution(args.tdevice)
    actions = parse_trace(trace_file)
    replay_script = transform_action(actions, log_dir, sensor_events)
    print(replay_script)
    full_path = os.path.abspath(trace_file)
    filename, file_extension = os.path.splitext(full_path)
    # svae replay script
    save_path = '_'.join([filename, 'widget_replay_%d_%d_%d' % (target_width, target_height, target_dpi)]) + '.py'
    with codecs.open(save_path, 'w', encoding='utf8') as f:
        f.write(replay_script)
