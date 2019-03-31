import pickle
import os
import re

stop_words = ['NS_AVAILABLE', 'NS_DEPRECATED', 'NS_DESIGNATED_INITIALIZER', '__OSX_AVAILABLE_STARTING']
prototypes = dict()
inheritance_chain = dict()

dir = '/home/gjy/Desktop/tmp/headers/'
for f in os.listdir(dir):
    fp = os.path.join(dir, f)
    file = open(fp)

    current_class = None
    current_protocol = None
    for line in file.readlines():
        m = re.search('@interface\s+(?P<class>\w+)\s+', line)
        if m:
            current_class = m.group('class')
            current_protocol = None
            if current_class not in prototypes:
                prototypes[current_class] = dict()
                m = re.search('@interface\s+(?P<class>\w+)[\s:]+(?P<superclass>\w+)\s+', line)
                if m:
                    inheritance_chain[current_class] = m.group('superclass')
                continue

        m = re.search('@protocol\s+(?P<proto>\w+)\s+', line)
        if m:
            current_protocol = m.group('proto')
            current_class = None
            if current_class not in prototypes:
                prototypes[current_protocol] = dict()
                continue

        m = re.match('[+-] \((?P<ret>[^:]+)\)(?P<sel>[^;\n]+);\n', line)
        if m:
            ret = m.group('ret')
            sel = m.group('sel')
            if ';' in sel:  # 'initWithCoder:(NSCoder *)aDecoder; // NS_DESIGNATED_INITIALIZER'
                sel = sel.split(';')[0]
            for word in stop_words:
                if word in sel:  # 'callStackReturnAddresses NS_AVAILABLE(10_5, 2_0)'
                    sel = sel.split(word)[0].strip()
            _sel = []
            _args = []
            if ':' in sel:
                for item in re.findall('(?P<meth>[^:\s]+):\((?P<type>[^:]+)\)', sel):
                    _sel.append(item[0])
                    _args.append(item[1])
                sel = ":".join(_sel) + ':'
            types = [ret, ] + _args
            # print sel
            if current_protocol:
                if sel not in prototypes[current_protocol]:
                    prototypes[current_protocol][sel] = types
                else:
                    print 'CONFLICT'
            if current_class:
                if sel not in prototypes[current_class]:
                    prototypes[current_class][sel] = types
                else:
                    pass
                    # print 'CONFLICT', current_class, sel, types, prototypes[current_class][sel]
            # print sel, types, line, f
            continue

        if line.startswith('@property'):
            line = line.split(';')[0]
            for word in stop_words:
                if word in line:
                    line = line.split(word)[0].strip()
            m = re.match('@property\s*\((?P<attr>.+)\)\s+(?P<rest>.+)', line)
            if m:
                rest = m.group('rest').split()
                prop = {
                    'type': rest[0],
                    'name': rest[-1],
                    'proto': rest[1] if len(rest) == 3 else None
                }
                if current_class:
                    if prop['name'] not in prototypes[current_class]:
                        prototypes[current_class][prop['name']] = [prop['type'], ]
                    else:
                        pass
                        print 'CONFLICT'
                if current_protocol:
                    if prop['name'] not in prototypes[current_protocol]:
                        prototypes[current_protocol][prop['name']] = [prop['type'], ]
                    else:
                        pass
                        print 'CONFLICT'
            continue

    file.close()

s = set()
for c in prototypes:
    for sel in prototypes[c]:
        type = prototypes[c][sel][0].strip('*').strip()
        if type not in prototypes:
            s.add(type)
for i in s:
    print i


f = open('/home/gjy/Desktop/MachOA/dbs/FrameworkHeaders.pkl', 'wb')
pickle.dump([prototypes, inheritance_chain], f)
f.close()
