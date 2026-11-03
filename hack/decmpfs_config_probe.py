"""Read-only capture of the observed native type-configuration table.

This compiler-specific recognizer preserves raw fields, never assigns codecs
or enables writes. Unknown instruction shapes produce no table claim.
"""
import hashlib
import struct

import decmpfs_binary_probe as probe


def configuration_candidate(window):
    code = bytes.fromhex(window['bytes_hex'])
    origin = int(window['address'], 16)
    words = struct.unpack('<' + 'I' * (len(code) // 4), code)
    for index in range(13, len(words) - 10):
        part = words[index:index + 11]
        if part[0:2] != (0x8B080509, 0xD37EF52A):
            continue
        adrp, add = part[2:4]
        if adrp & 0x9F00001F != 0x9000000B or add & 0xFFC003FF != 0x9100016B:
            continue
        if part[4:11] != (0xEB2AC15F, 0x8B2AC169, 0x8B0A0170, 0xF2E575B0,
                          0x9A900129, 0xB940012A, 0x3400006A):
            continue
        earlier = words[index - 13:index - 8]
        load_ptr, load_type, subtract, compare, branch = earlier
        count = subtract >> 10 & 4095
        if load_ptr != 0xF9400828 or load_type != 0xB9400908:
            continue
        if subtract & 0xFFC003FF != 0x51000109 or compare & 0xFFC003FF != 0x3100013F:
            continue
        if compare >> 10 & 4095 != count or not 2 <= count <= 65:
            continue
        branch_pc = origin + (index - 9) * 4
        target = branch_pc + (probe.signed(branch >> 5 & 0x7FFFF, 19) << 2)
        if branch & 0xFF00001F != 0x54000008 or target != origin + index * 4:
            continue
        constants = probe.local_constants(struct.pack('<2I', adrp, add), origin + (index + 2) * 4)
        if 11 in constants:
            return {'address': constants[11], 'count': count, 'stride': 12,
                    'lookup_address': hex(origin + index * 4),
                    'helper_window_sha256': window['sha256']}
    return None


def configuration_table(image, candidate):
    address, count = candidate['address'], candidate['count']
    length = count * 12
    for section in image.sections:
        delta = address - section['address']
        if section['flags'] & 255 in (1, 12, 18) or not 0 <= delta <= section['size'] - length:
            continue
        offset = section['offset'] + delta
        raw = image.read(offset, length)
        return {**candidate, 'address': hex(address), 'file_offset': image.base + offset,
                'bytes_hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                'entries': [{'type_index': index, 'raw_words': list(probe.unpack('<3I', raw, index * 12))}
                            for index in range(count)]}
    raise probe.EvidenceError('type-configuration table is outside file-backed sections')


def inspect_configuration(image, table, capture):
    seen, results = set(), []
    for entry in table['entries']:
        for callback in entry.get('registration', {}).get('callbacks', []):
            window = callback.get('code_window')
            if callback['field'] != 'fetch' or not window:
                continue
            for branch in window['direct_branches']:
                target = int(branch['target'], 16)
                if branch['instruction'] != 'BL' or target in seen:
                    continue
                seen.add(target)
                helper = capture(image, target)
                if helper:
                    candidate = configuration_candidate(helper)
                    if candidate:
                        results.append({'fetch_branch': branch, 'helper_window': helper,
                                        'configuration': configuration_table(image, candidate)})
    return results
