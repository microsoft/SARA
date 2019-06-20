# coding=utf8

import re
from lxml import builder, etree
C = builder.ElementMaker()


VIEW_ATTR_PATTERN = re.compile(r'^(?P<classname>[\.a-zA-Z0-9$]*)\{(?P<address>.*)\s(?P<visible>.)(?P<focusable>.)(?P<enabled>.)(?P<draw_mask>.)(?P<scroll_horiz>.)(?P<scroll_verti>.)(?P<clickable>.)(?P<long_clickable>.)((?P<context_clickable>.)\s|\s)(.+)\s(?P<left>-?\d+),(?P<top>-?\d+)\-(?P<right>-?\d+),(?P<bottom>-?\d+)((\s(?P<view_id>#[a-zA-Z0-9]+)\s(?P<resource_id>.+))|(\s*(.*)))\}')
VIEW_HIERARCHY_PATTERN = re.compile(r'\s+View Hierarchy:')


def get_view_address(view_str):
    view_attrs = parse_view(view_str)
    if view_attrs is None:
        return None
    return view_attrs['address']


def calc_indent(line):
    strip = line.lstrip()
    return len(line) - len(strip), strip


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


def assign_tag_attrs(tag, attrs):
    for key, value in attrs.items():
        tag.attrib[key] = value if value is not None else ''


def preprocess(lines):
    result = list()
    while lines:
        line = lines.pop(0)
        if len(line.strip()) == 0:
            continue
        attrs = parse_view(line)
        if attrs is not None:
            lines.insert(0, line)
            break
    for line in lines:
        if len(line.strip()) == 0:
            continue
        attrs = parse_view(line)
        if attrs is None:
            continue
        result.append((line, attrs))
    return result


def find_view_hierarchy_block(content):

    idx_list = list()
    for idx, line in enumerate(content.split('\n')):
        if VIEW_HIERARCHY_PATTERN.match(line):
            idx_list.append(idx)
    if len(idx_list) > 0:
        return '\n'.join(content.split('\n')[idx_list[-1]:])
    return None

def read_view_hierarchy(content):
    view_hierarchy_str = find_view_hierarchy_block(content)
    if view_hierarchy_str is None:
        print(content)
        print('Fail to parse')
        return

    # Build tree
    top = current_block = C.config()
    stack = list()
    
    lines = view_hierarchy_str.split('\n')
    lines = preprocess(lines)

    current_indent, _ = calc_indent(lines[0][0])
    while lines:
        (line, view_attrs) = lines.pop(0)
        indent, line = calc_indent(line)

        if indent == current_indent:
            pass
        elif indent > current_indent:
            # we've gone down a level, convert the cmd to a block and then save the current indent and block to the stack
            prev.tag = 'view'
            # prev.append(C.name(prev.text))
            prev.text = None
            stack.insert(0, (current_indent, current_block,))
            current_indent = indent
            current_block = prev
        else:
            # indent < current_indent
            # Pop the stack until we find out which level and return to it 
            found = False
            while stack:
                parent_indent, parent_block = stack.pop(0)
                if parent_indent == indent:
                    found = True
                    break
            if not found:
                raise Exception('Indent not found in parent stack')
            current_indent = indent
            current_block = parent_block
        prev = C.view(line)
        assign_tag_attrs(prev, view_attrs)
        current_block.append(prev)
    return top


if __name__ == '__main__':
    with open('..\\amaze.xml', 'r') as f:
        root = read_view_hierarchy(f.read())
    print(etree.tostring(root, pretty_print=True).decode())
    with open('dialog.xml', 'wb') as f:
        f.write(etree.tostring(root, pretty_print=True))