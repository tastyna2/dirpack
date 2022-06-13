import numpy as np
from sklearn.preprocessing import OneHotEncoder, LabelEncoder

class FeatureType(object):

    name = ''
    dim = 0

    def process_raw_features(self, raw_obj):
        raise (NotImplementedError)

class EntryPoint(FeatureType):

    name = 'entrypoint'
    dim = 1

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return self.name

    def process_raw_features(self, raw_obj):
        return np.array(raw_obj)

class VirtualSize(FeatureType):

    name = 'virtual_size'
    dim = 1

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return self.name

    def process_raw_features(self, raw_obj):
        return np.array(raw_obj)

class DOSHeader(FeatureType):

    name = 'dos_header'
    dim = 31

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return ['magic', 'used_bytes_in_the_last_page', 'file_size_in_pages', 'numberof_relocation',
            'header_size_in_paragraphs', 'maximum_extra_paragraphs', 'minimum_extra_paragraphs',
            'initial_relative_ss', 'initial_sp', 'checksum', 'initial_ip', 'initial_relative_cs',
            'addressof_relocation_table', 'overlay_number', 'reserved(1)', 'reserved(2)', 'reserved(3)',
            'reserved(4)', 'oem_id', 'oem_info', 'reserved2(1)', 'reserved2(2)', 'reserved2(3)', 'reserved2(4)',
            'reserved2(5)', 'reserved2(6)', 'reserved2(7)', 'reserved2(8)', 'reserved2(9)', 'reserved2(10)',
            'addressof_new_exeheader']

    def process_raw_features(self, raw_obj):
        return np.hstack([
            raw_obj['magic'], raw_obj['used_bytes_in_the_last_page'], raw_obj['file_size_in_pages'],
            raw_obj['numberof_relocation'], raw_obj['header_size_in_paragraphs'], raw_obj['maximum_extra_paragraphs'],
            raw_obj['minimum_extra_paragraphs'], raw_obj['initial_relative_ss'], raw_obj['initial_sp'],
            raw_obj['checksum'], raw_obj['initial_ip'], raw_obj['initial_relative_cs'], raw_obj['addressof_relocation_table'],
            raw_obj['overlay_number'], np.array(raw_obj['reserved']), raw_obj['oem_id'], raw_obj['oem_info'],
            np.array(raw_obj['reserved2']), raw_obj['addressof_new_exeheader']
        ])

class RichHeader(FeatureType):

    name = 'rich_header'
    dim = 1 + 56 + 151

    def __init__(self):
        super(FeatureType, self).__init__()
        self.pair_ids = [(0, 0), (0, 1), (30729, 147), (7299, 14), (0, 151), (30729, 131), (41118, 199),
            (4035, 93), (50727, 123), (65501, 203), (24123, 261), (24123, 260), (24123, 259),
            (21005, 219), (1735, 6), (8168, 11), (24210, 255), (8168, 10), (26706, 261), (26706, 260),
            (4035, 95), (26706, 259), (7291, 12), (50727, 109), (8034, 19), (24215, 258), (21005, 225),
            (21005, 224), (24123, 257), (21005, 223), (40629, 222), (40219, 157), (8169, 13),
            (30729, 132), (21022, 148), (2179, 93), (24215, 256), (50727, 120), (30729, 145),
            (50727, 110), (20806, 225), (8078, 19), (8041, 9), (50727, 124), (40116, 242), (30729, 149),
            (40219, 171), (50727, 125), (26706, 257), (40116, 243), (40116, 241), (8047, 10),
            (26213, 257), (1720, 6), (21022, 132), (21022, 131), (8444, 18), (21022, 145), (24215, 261),
            (9782, 11), (24215, 257), (8047, 4), (21022, 149), (40219, 170), (9210, 25), (21005, 221),
            (40219, 158), (40219, 154), (40629, 220), (9782, 13), (4035, 94), (4035, 90), (40629, 221),
            (8168, 22), (8168, 4), (8047, 11), (4035, 15), (25711, 257), (4035, 96), (20413, 150),
            (8783, 9), (50929, 207), (50929, 206), (20806, 224), (30319, 171), (20115, 152), (30729, 146),
            (9178, 28), (20806, 223), (40219, 156), (40629, 224), (50929, 205), (65501, 206),
            (40629, 225), (8447, 4), (31101, 222), (25203, 257), (20806, 221), (9782, 10), (23013, 261),
            (30716, 185), (30729, 138), (25711, 260), (23917, 257), (61030, 204), (30319, 170),
            (26213, 260), (9044, 48), (50327, 126), (24215, 265), (40219, 155), (21022, 147),
            (30319, 157), (40219, 175), (24215, 260), (9782, 4), (30729, 148), (3077, 96), (30319, 158),
            (50727, 122), (50727, 114), (40629, 223), (25930, 261), (9111, 69), (3077, 90), (65501, 208),
            (25930, 260), (25930, 259), (3052, 94), (3077, 15), (40116, 239), (3077, 95), (31101, 220),
            (9210, 61), (31101, 221), (50929, 203), (40629, 234), (61030, 201), (2067, 93), (26131, 261),
            (31101, 225), (25930, 257), (26131, 260), (26131, 259), (61030, 202), (26213, 261),
            (26213, 259), (27027, 258), (9178, 29), (27027, 255), (26715, 257)]
        self.pair_num = len(self.pair_ids)
        self.build_ids = [0, 30729, 7299, 50727, 4035, 41118, 65501, 8168, 24123, 21005, 1735,
            24210, 9782, 21022, 24215, 26706, 7291, 40219, 8034, 40629, 40116, 8169, 8047, 2179,
            20806, 8078, 8041, 26213, 1720, 8444, 9210, 25711, 30319, 8447, 20413, 8783, 50929,
            9178, 25203, 31101, 20115, 9044, 3077, 23013, 30716, 61030, 23917, 2067, 50327, 9111,
            25930, 3052, 27027, 26131, 8966, 26715]
        self.build_num = len(self.build_ids)

    def name_strings(self):
        return ['key'] +  ['build_id:' + str(build) for build in self.build_ids
            ] + ['(build_id, id):' + str(pair) for pair in self.pair_ids]

    def process_raw_features(self, raw_obj):
        rich = np.zeros(self.build_num + self.pair_num)
        if raw_obj is None:
            return np.hstack([0, rich])
        else:
            for i in range(self.build_num):
                for e in raw_obj['entries']:
                    if e['build_id'] == self.build_ids[i]:
                        rich[i] += e['count']
            for i in range(self.pair_num):
                for e in raw_obj['entries']:
                    if e['build_id'] == self.pair_ids[i][0] and e['id'] == self.pair_ids[i][1]:
                        rich[self.build_num + i] += e['count']
            return np.hstack([raw_obj['key'], rich])

class Header(FeatureType):

    name = 'header'
    dim = 1 * 5 + 4 + 27 + 16

    def __init__(self):
        super(FeatureType, self).__init__()
        self.ohe = OneHotEncoder( categories=[["INVALID","UNKNOWN","AM33","AMD64","ARM","ARMNT","ARM64",
            "EBC","I386","IA64","M32R","MIPS16","MIPSFPU","MIPSFPU16","POWERPC","POWERPCFP","R4000",
            "RISCV32","RISCV64","RISCV128","SH3","SH3DSP","SH4","SH5","THUMB","WCEMIPSV2",
            "Out of range"]], handle_unknown='ignore', sparse=False )
        self.ohe.fit([['INVALID']])

    def name_strings(self):
        return ['signature(1)', 'signature(2)', 'signature(3)', 'signature(4)', 'machine:INVALID',
            'machine:UNKNOWN','machine:AM33','machine:AMD64','machine:ARM','machine:ARMNT','machine:ARM64',
            'machine:EBC','machine:I386','machine:IA64','machine:M32R','machine:MIPS16','machine:MIPSFPU',
            'machine:MIPSFPU16','machine:POWERPC','machine:POWERPCFP','machine:R4000','machine:RISCV32',
            'machine:RISCV64','machine:RISCV128','machine:SH3','machine:SH3DSP','machine:SH4','machine:SH5',
            'machine:THUMB','machine:WCEMIPSV2','machine:Out of range','numberof_sections', 'time_date_stamp',
            'numberof_symbols','pointerto_symbol_table','sizeof_optional_header', 'characteristics:RELOCS_STRIPPED',
            'characteristics:EXECUTABLE_IMAGE', 'characteristics:LINE_NUMS_STRIPPED', 'characteristics:LOCAL_SYMS_STRIPPED',
            'characteristics:AGGRESSIVE_WS_TRIM','characteristics:LARGE_ADDRESS_AWARE', 'characteristics:RESERVED',
            'characteristics:BYTES_REVERSED_LO', 'characteristics:32BIT_MACHINE', 'characteristics:DEBUG_STRIPPED',
            'characteristics:REMOVABLE_RUN_FROM_SWAP', 'characteristics:NET_RUN_FROM_SWAP', 'characteristics:SYSTEM', 'characteristics:DLL', 'characteristics:UP_SYSTEM_ONLY', 'characteristics:BYTES_REVERSED_HI']

    def process_raw_features(self, raw_obj):
        return np.hstack([
            np.array(raw_obj['signature']), self.ohe.transform([[raw_obj['machine']]]).reshape(-1),
            raw_obj['numberof_sections'], raw_obj['time_date_stamp'], raw_obj['numberof_symbols'],
            raw_obj['pointerto_symbol_table'], raw_obj['sizeof_optional_header'],
            np.array([float(x) for x in reversed(format(raw_obj['characteristics'], '016b'))])
        ])

class OptionalHeader(FeatureType):

    name = 'optional_header'
    dim = 15 + 16 + 28

    def __init__(self):
        super(FeatureType, self).__init__()
        self.size = 1
        self.le = LabelEncoder()
        self.ohe = OneHotEncoder( categories=[['UNKNOWN','NATIVE','WINDOWS_GUI','WINDOWS_CUI','OS2_CUI',
            'POSIX_CUI','NATIVE_WINDOWS','WINDOWS_CE_GUI','EFI_APPLICATION','EFI_BOOT_SERVICE_DRIVER',
            'EFI_RUNTIME_DRIVER','EFI_ROM','XBOX','WINDOWS_BOOT_APPLICATION','Out of range']],
            handle_unknown='ignore', sparse=False )
        self.le.fit(['PE32', 'PE32_PLUS'])
        self.ohe.fit([['UNKNOWN']])

    def name_strings(self):
        return ['magic', 'major_linker_version', 'minor_linker_version', 'sizeof_code/size', 'sizeof_initialized_data/size',
            'sizeof_uninitialized_data/size', 'addressof_entrypoint', 'baseof_code', 'baseof_data',
            'imagebase', 'section_alignment', 'file_alignment', 'major_operating_system_version',
            'minor_operating_system_version', 'major_image_version', 'minor_image_version', 'major_subsystem_version',
            'minor_subsystem_version', 'win32_version_value', 'sizeof_image/size', 'sizeof_headers/size',
            'checksum', 'subsystem:UNKNOWN','subsystem:NATIVE','subsystem:WINDOWS_GUI','subsystem:WINDOWS_CUI',
            'subsystem:OS2_CUI','subsystem:POSIX_CUI','subsystem:NATIVE_WINDOWS','subsystem:WINDOWS_CE_GUI',
            'subsystem:EFI_APPLICATION','subsystem:EFI_BOOT_SERVICE_DRIVER','subsystem:EFI_RUNTIME_DRIVER',
            'subsystem:EFI_ROM','subsystem:XBOX','subsystem:WINDOWS_BOOT_APPLICATION','subsystem:Out of range',
            'dll_characteristics:RESERVED1','dll_characteristics:RESERVED2','dll_characteristics:RESERVED3',
            'dll_characteristics:RESERVED4','dll_characteristics:RESERVED5','dll_characteristics:HIGH_ENTROPY_VA',
            'dll_characteristics:DYNAMIC_BASE','dll_characteristics:FORCE_INTEGRITY','dll_characteristics:NX_COMPAT',
            'dll_characteristics:NX_ISOLATION','dll_characteristics:NO_SEH','dll_characteristics:NO_BIND',
            'dll_characteristics:APPCONTAINER','dll_characteristics:WDM_DRIVER','dll_characteristics:GUARD_CF',
            'dll_characteristics:TERMINAL_SERVER_AWARE','sizeof_stack_reserve/size', 'sizeof_stack_commit/size',
            'sizeof_heap_reserve/size','sizeof_heap_commit/size','loader_flags', 'numberof_rva_and_size']

    def set_size(self, filesz):
        self.size = int(filesz)

    def process_raw_features(self, raw_obj):
        return np.hstack([
            self.le.transform([raw_obj['magic']]), raw_obj['major_linker_version'], raw_obj['minor_linker_version'],
            raw_obj['sizeof_code'] / self.size, raw_obj['sizeof_initialized_data'] / self.size,
            raw_obj['sizeof_uninitialized_data'] / self.size, raw_obj['addressof_entrypoint'],
            raw_obj['baseof_code'], raw_obj.get('baseof_data', 0), raw_obj['imagebase'], raw_obj['section_alignment'],
            raw_obj['file_alignment'], raw_obj['major_operating_system_version'], raw_obj['minor_operating_system_version'],
            raw_obj['major_image_version'], raw_obj['minor_image_version'], raw_obj['major_subsystem_version'],
            raw_obj['minor_subsystem_version'], raw_obj['win32_version_value'], raw_obj['sizeof_image'] / self.size,
            raw_obj['sizeof_headers'] / self.size, raw_obj['checksum'], self.ohe.transform([[raw_obj['subsystem']]]).reshape(-1),
            np.array([float(x) for x in reversed(format(raw_obj['dll_characteristics'], '016b'))]),
            raw_obj['sizeof_stack_reserve'] / self.size, raw_obj['sizeof_stack_commit'] / self.size,
            raw_obj['sizeof_heap_reserve'] / self.size, raw_obj['sizeof_heap_commit'] / self.size, raw_obj['loader_flags'],
            raw_obj['numberof_rva_and_size']
        ])

class DataDirectories(FeatureType):

    name = 'data_directories'
    dim = 15 * 2

    def __init__(self):
        super(FeatureType, self).__init__()
        self._name_order = [
            "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "CERTIFICATE_TABLE",
            "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE",
            "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"
        ]

    def name_strings(self):
        return ['EXPORT_TABLE:RVA', 'EXPORT_TABLE:size', 'IMPORT_TABLE:RVA', 'IMPORT_TABLE:size',
            'RESOURCE_TABLE:RVA', 'RESOURCE_TABLE:size', 'EXCEPTION_TABLE:RVA', 'EXCEPTION_TABLE:size',
            'CERTIFICATE_TABLE:RVA', 'CERTIFICATE_TABLE:size', 'BASE_RELOCATION_TABLE:RVA', 'BASE_RELOCATION_TABLE:size',
            'DEBUG:RVA', 'DEBUG:size', 'ARCHITECTURE:RVA', 'ARCHITECTURE:size', 'GLOBAL_PTR:RVA',
            'GLOBAL_PTR:size', 'TLS_TABLE:RVA', 'TLS_TABLE:size', 'LOAD_CONFIG_TABLE:RVA', 'LOAD_CONFIG_TABLE:size',
            'BOUND_IMPORT:RVA', 'BOUND_IMPORT:size', 'IAT:RVA', 'IAT:size', 'DELAY_IMPORT_DESCRIPTOR:RVA',
            'DELAY_IMPORT_DESCRIPTOR:size', 'CLR_RUNTIME_HEADER:RVA', 'CLR_RUNTIME_HEADER:size']

    def process_raw_features(self, raw_obj):
        features = np.zeros(2 * len(self._name_order))
        rest = list(range(len(raw_obj)))
        for i in range(len(self._name_order)):
            for j in rest:
                if raw_obj[j]['type'] == self._name_order[i]:
                    features[2 * i] = raw_obj[j]['RVA']
                    features[2 * i + 1] = raw_obj[j]['size']
                    rest.remove(j)
                    break
        return features

class Sections(FeatureType):

    name = 'sections'
    dim =  6 * 48 + 35 + 11

    def __init__(self):
        super(FeatureType, self).__init__()
        self.ch_names = [
            "TYPE_NO_PAD","CNT_CODE","CNT_INITIALIZED_DATA","CNT_UNINITIALIZED_DATA",
            "LNK_OTHER","LNK_INFO","LNK_REMOVE","LNK_COMDAT","GPREL","MEM_PURGEABLE",
            "MEM_16BIT","MEM_LOCKED","MEM_PRELOAD","ALIGN_1BYTES","ALIGN_2BYTES",
            "ALIGN_4BYTES","ALIGN_8BYTES","ALIGN_16BYTES","ALIGN_32BYTES","ALIGN_64BYTES",
            "ALIGN_128BYTES","ALIGN_256BYTES","ALIGN_512BYTES","ALIGN_1024BYTES",
            "ALIGN_2048BYTES","ALIGN_4096BYTES","ALIGN_8192BYTES","LNK_NRELOC_OVFL",
            "MEM_DISCARDABLE","MEM_NOT_CACHED","MEM_NOT_PAGED","MEM_SHARED","MEM_EXECUTE",
            "MEM_READ","MEM_WRITE"
        ]
        self.ch_num = len(self.ch_names)
        self.ch_index = dict(zip(self.ch_names, range(self.ch_num)))
        self.sec_names = ['', '.rsrc', '.text', '.data', '.rdata', '.idata', '.bss', '.tls',
            '.CRT', '/4', '.reloc', 'packerBY', 'bero^fr ', 'yC', '.packed', '.RLPack',
            '.aspack', '.adata', '.PACKMAN', 'MEW', '\x02\\xd2u\\xdb\\x8a\x16\\xeb\\xd4', '.yP',
            '.rsrc   ', 'petite', 'UPX0', 'UPX1', '.MPRESS1', '.MPRESS2', '.gfids', 'UPX2',
            '.00cfg', '.xdata', '_winzip_', '.eh_fram', 'CODE', 'DATA', 'BSS', '.edata',
            '.itext', '.didata', 'code', 'data', 'const', '.qtmetad', '.buildid', '.shared',
            '.giats', '\x1e\x1a\x06]\x180\x10\\']
        self.sec_num = len(self.sec_names)
        self.attr_names = ['exist', 'pointerto_relocation', 'pointerto_line_numbers', 'numberof_relocations',
            'numberof_line_numbers', 'entropy']
        self.attr_num = len(self.attr_names)
        self.type_names = ['TEXT', 'TLS_', 'IDATA', 'DATA', 'BSS', 'RESOURCE', 'RELOCATION',
            'EXPORT', 'DEBUG', 'UNKNOWN', 'Out of range']
        self.type_num = len(self.type_names)
        self.type_index = dict(zip(self.type_names, range(self.type_num)))

    def name_strings(self):
        return ['name:' + n + ':' + attr for n in self.sec_names for attr in self.attr_names] + [
            'characteristics:' + chs for chs in self.ch_names] + ['types:' + t for t in self.type_names]

    def process_raw_features(self, raw_obj):
        sec_data = np.zeros(self.attr_num * self.sec_num)
        characteristics = np.zeros(self.ch_num)
        types = np.zeros(self.type_num)
        for i in range(self.sec_num):
            for s in raw_obj:
                if self.sec_names[i] == s['name']:
                    sec_data[self.attr_num * i] = 1
                    for j in range(1, self.attr_num):
                        sec_data[self.attr_num * i + j] = s[self.attr_names[j]]
        for s in raw_obj:
            for c in s['characteristics']:
                characteristics[self.ch_index[c]] += 1
            for t in s['types']:
                types[self.type_index[t]] += 1

        return np.hstack([sec_data, characteristics, types])

class Relocations(FeatureType):

    name = 'relocations'
    dim = 13

    def __init__(self):
        super(FeatureType, self).__init__()
        self.type_names = ["ABSOLUTE", "HIGH", "LOW", "HIGHLOW", "HIGHADJ",
            "MIPS_JMPADDR | ARM_MOV32A | ARM_MOV32 | RISCV_HI20", "SECTION",
            "REL | ARM_MOV32T | THUMB_MOV32 | RISCV_LOW12I", "RISCV_LOW12S",
            "MIPS_JMPADDR16 | IA64_IMM64", "DIR64", "HIGH3ADJ", "Out of range"]
        self.type_num = len(self.type_names)
        self.type_index = dict(zip(self.type_names, range(self.type_num)))

    def name_strings(self):
        return self.type_names

    def process_raw_features(self, raw_obj):
        types = np.zeros(self.type_num)
        if raw_obj is None:
            return types
        else:
            for r in raw_obj:
                for e in r['entries']:
                    types[self.type_index[e['type']]] += 1
            return types

class Tls(FeatureType):

    name = 'tls'
    dim = 1 * 6 + 15 + 15

    def __init__(self):
        super(FeatureType, self).__init__()
        self.align_index = {}
        for i in range(0x1,0xf):
            self.align_index[i << 20] = i - 1
        len_valid = len(self.align_index)
        self.align_index[0x0] = len_valid
        self.align_index[0xf << 20] = len_valid
        self.directory_names = ["EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
            "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR",
            "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR",
            "CLR_RUNTIME_HEADER"]
        self.directory_num = len(self.directory_names)
        self.directory_index = dict(zip(self.directory_names, range(self.directory_num)))

    def name_strings(self):
        return ['num of callbacks', 'num of addressof_raw_data', 'addressof_index', 'addressof_callbacks',
            'sizeof_zero_fill'] + ['characteristics:ALIGN_' + str(2 ** i) + 'BYTES' for i in range(14)
            ] + ['characteristics:ALIGN_??', 'characteristics:has_extra_bits'] + ['data_directory:'
            + n for n in self.directory_names]

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(self.dim)
        else:
            characteristics = np.zeros(0xf)
            characteristics[self.align_index[raw_obj['characteristics'] & 0xF00000]] += 1
            has_extra_bits = int((raw_obj['characteristics'] & 0xFF0FFFFF) != 0)
            directory_array = np.zeros(self.directory_num)
            data_directory = raw_obj.get('data_directory')
            if data_directory is not None:
                directory_array[self.directory_index[data_directory]] = 1
            return np.hstack([
                len(raw_obj['callbacks']), len(raw_obj['addressof_raw_data']), raw_obj['addressof_index'],
                raw_obj['addressof_callbacks'], raw_obj['sizeof_zero_fill'], characteristics, has_extra_bits,
                directory_array
            ])

class Export(FeatureType):
    name = 'export'
    dim = 6

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return ['export_flags', 'timestamp', 'major_version', 'minor_version', 'ordinal_base', 'num of apis']

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(6)
        return np.array([
            raw_obj['export_flags'], raw_obj['timestamp'], raw_obj['major_version'],
            raw_obj['minor_version'], raw_obj['ordinal_base'], len(raw_obj['entries'])
        ])

class Debug(FeatureType):
    name = 'debug'
    dim = 19 + 5 + 3

    def __init__(self):
        super(FeatureType, self).__init__()
        self.type_names = ["UNKNOWN", "COFF", "CODEVIEW", "FPO", "MISC", "EXCEPTION", "FIXUP",
            "OMAP_TO_SRC", "OMAP_FROM_SRC", "BORLAND", "RESERVED", "CLSID", "VC_FEATURE", "POGO",
            "ILTCG", "MPX", "REPRO", "EX_DLLCHARACTERISTICS", "Out of range"]
        self.type_num = len(self.type_names)
        self.type_index = dict(zip(self.type_names, range(self.type_num)))
        self.cv_names = ["UNKNOWN", "PDB_70", "PDB_20", "CV_50", "CV_41"]
        self.cv_num = len(self.cv_names)
        self.cv_index = dict(zip(self.cv_names, range(self.cv_num)))
        self.pogo_names = ["UNKNOWN", "LCTG", "PGI"]
        self.pogo_num = len(self.pogo_names)
        self.pogo_index = dict(zip(self.pogo_names, range(self.pogo_num)))

    def name_strings(self):
        return self.type_names + self.cv_names + self.pogo_names

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(self.type_num + self.cv_num + self.pogo_num)
        type = np.zeros(self.type_num)
        cv_sig = np.zeros(self.cv_num)
        pogo_sig = np.zeros(self.pogo_num)
        for d in raw_obj:
            type[self.type_index[d['type']]] += 1
            raw_cv = d.get('code_view')
            if raw_cv is not None:
                cv_sig[self.cv_index[raw_cv['cv_signature']]] += 1
            raw_pogo = d.get('pogo')
            if raw_pogo is not None:
                pogo_sig[self.pogo_index[raw_pogo['signature']]] += 1
        return np.hstack([type, cv_sig, pogo_sig])

class Imports(FeatureType):

    name = 'imports'
    dim = 5 * 72

    def __init__(self):
        super(FeatureType, self).__init__()
        self.dll_names = ['kernel32.dll', 'user32.dll', 'advapi32.dll', 'oleaut32.dll', 'shell32.dll',
            'ole32.dll', 'gdi32.dll', 'comctl32.dll', 'msvcrt.dll', 'mscoree.dll', 'version.dll',
            'shlwapi.dll', 'api-ms-win-crt-runtime-l1-1-0.dll', 'vcruntime140.dll', 'wininet.dll',
            'api-ms-win-crt-heap-l1-1-0.dll', 'ws2_32.dll', 'winmm.dll', 'comdlg32.dll', 'api-ms-win-crt-stdio-l1-1-0.dll',
            'wsock32.dll', 'api-ms-win-crt-string-l1-1-0.dll', 'mpr.dll', 'msvcp140.dll', 'api-ms-win-crt-math-l1-1-0.dll',
            'winspool.drv', 'msvbvm60.dll', 'api-ms-win-crt-convert-l1-1-0.dll', 'iphlpapi.dll',
            'ntdll.dll', 'psapi.dll', 'msimg32.dll', 'qt5core.dll', 'msvcr120.dll', 'gdiplus.dll',
            'userenv.dll', 'api-ms-win-crt-locale-l1-1-0.dll', 'urlmon.dll', 'crypt32.dll',
            'api-ms-win-crt-time-l1-1-0.dll', 'api-ms-win-crt-filesystem-l1-1-0.dll', 'api-ms-win-crt-utility-l1-1-0.dll',
            'uxtheme.dll', 'rpcrt4.dll', 'qt5gui.dll', 'api-ms-win-crt-environment-l1-1-0.dll',
            'msvcp120.dll', 'netapi32.dll', 'imm32.dll', 'winhttp.dll', 'setupapi.dll', 'crtdll.dll',
            'msvcr90.dll', 'msvcr100.dll', 'rtl120.bpl', 'oleacc.dll', 'libvlccore.dll', 'qt5widgets.dll',
            'libstdc++-6.dll', 'wtsapi32.dll', 'msvcr80.dll', 'vcl120.bpl', 'msvcr110.dll', 'rtl70.bpl',
            'dbghelp.dll', 'oledlg.dll', 'avutil-50.dll', 'rtl160.bpl', 'vcl70.bpl', 'mfc42.dll',
            'wintrust.dll', 'shfolder.dll']
        self.dll_num = len(self.dll_names)
        self.attr_names = ['num of api', 'forwarder_chain', 'timedatestamp',
            'import_address_table_rva', 'import_lookup_table_rva']
        self.attr_num = len(self.attr_names)

    def name_strings(self):
        return [dll + ':' + attr for dll in self.dll_names for attr in self.attr_names]

    def process_raw_features(self, raw_obj):
        dlls = np.zeros(self.attr_num * self.dll_num)
        if raw_obj is None:
            return dlls
        else:
            for i in range(self.dll_num):
                for dll in raw_obj:
                    if dll['name'].lower() == self.dll_names[i]:
                        dlls[self.attr_num * i] = len(dll['entries'])
                        for j in range(1, self.attr_num):
                            dlls[self.attr_num * i + j] = dll[self.attr_names[j]]
            return dlls

class ResourcesTree(FeatureType):
    name = 'resources_tree'
    dim = 6

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return ['characteristics', 'time_date_stamp', 'major_version', 'minor_version',
            'numberof_name_entries', 'numberof_id_entries']

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(6)
        return np.array([
            raw_obj['characteristics'], raw_obj['time_date_stamp'], raw_obj['major_version'],
            raw_obj['minor_version'], raw_obj['numberof_name_entries'],
            raw_obj['numberof_id_entries']
        ])

class ResourcesManager(FeatureType):
    name = 'resources_manager'
    dim = 1 * 2 + 6 * 2 + 15 + 8 + 13 + 1 * 8 + 2 + 2 + 99 + 229 + 1 * 2

    def __init__(self):
        super(FeatureType, self).__init__()
        self.flags_value = [0x00000001, 0x00000010, 0x00000004, 0x00000002, 0x00000008, 0x00000020]
        self.flags_num = len(self.flags_value)
        self.os_names = ['UNKNOWN', 'DOS', 'NT', 'WINDOWS16', 'WINDOWS32', 'OS216', 'OS232',
            'PM16', 'PM32', 'DOS_WINDOWS16', 'DOS_WINDOWS32', 'NT_WINDOWS32', 'OS216_PM16',
            'OS232_PM32', 'Out of range']
        self.os_num = len(self.os_names)
        self.os_index = dict(zip(self.os_names, range(self.os_num)))
        self.type_names = ['APP', 'DLL', 'DRV', 'FONT', 'STATIC_LIB', 'VXD', 'UNKNOWN', 'Out of range']
        self.type_num = len(self.type_names)
        self.type_index = dict(zip(self.type_names, range(self.type_num)))
        self.subtype_names = ['DRV_COMM', 'DRV_DISPLAY', 'DRV_INSTALLABLE', 'DRV_KEYBOARD',
            'DRV_LANGUAGE', 'DRV_MOUSE', 'DRV_NETWORK', 'DRV_PRINTER', 'DRV_SOUND', 'DRV_SYSTEM',
            'DRV_VERSIONED_PRINTER', 'UNKNOWN', 'Out of range']
        self.subtype_num = len(self.subtype_names)
        self.subtype_index = dict(zip(self.subtype_names, range(self.subtype_num)))
        self.lang_names =["NEUTRAL","INVARIANT","AFRIKAANS","ALBANIAN","ARABIC","ARMENIAN",
            "ASSAMESE","AZERI","BASQUE","BELARUSIAN","BANGLA","BULGARIAN","CATALAN","CHINESE",
            "CROATIAN","CZECH","DANISH","DIVEHI","DUTCH","ENGLISH","ESTONIAN","FAEROESE","FARSI",
            "FINNISH","FRENCH","GALICIAN","GEORGIAN","GERMAN","GREEK","GUJARATI","HEBREW","HINDI",
            "HUNGARIAN","ICELANDIC","INDONESIAN","ITALIAN","JAPANESE","KANNADA","KASHMIRI","KAZAK",
            "KONKANI","KOREAN","KYRGYZ","LATVIAN","LITHUANIAN","MACEDONIAN","MALAY","MALAYALAM",
            "MANIPURI","MARATHI","MONGOLIAN","NEPALI","NORWEGIAN","ORIYA","POLISH","PORTUGUESE",
            "PUNJABI","ROMANIAN","RUSSIAN","SANSKRIT","SINDHI","SLOVAK","SLOVENIAN","SPANISH",
            "SWAHILI","SWEDISH","SYRIAC","TAMIL","TATAR","TELUGU","THAI","TURKISH","UKRAINIAN",
            "URDU","UZBEK","VIETNAMESE","MALTESE","MAORI","RHAETO_ROMANCE","SAMI","SORBIAN",
            "SUTU","TSONGA","TSWANA","VENDA","XHOSA","ZULU","ESPERANTO","WALON","CORNISH","WELSH",
            "BRETON","INUKTITUT","IRISH","PULAR","QUECHUA","TAMAZIGHT","TIGRINYA","Out of range"]
        self.lang_num = len(self.lang_names)
        self.lang_index = dict(zip(self.lang_names, range(self.lang_num)))
        self.sublang_names = ["AFRIKAANS_SOUTH_AFRICA","ALBANIAN_ALBANIA","ALSATIAN_FRANCE",
            "AMHARIC_ETHIOPIA","ARABIC_ALGERIA","ARABIC_BAHRAIN","ARABIC_EGYPT","ARABIC_IRAQ",
            "ARABIC_JORDAN","ARABIC_KUWAIT","ARABIC_LEBANON","ARABIC_LIBYA","ARABIC_MOROCCO",
            "ARABIC_OMAN","ARABIC_QATAR","ARABIC_SAUDI_ARABIA","ARABIC_SYRIA","ARABIC_TUNISIA",
            "ARABIC_UAE","ARABIC_YEMEN","ARMENIAN_ARMENIA","ASSAMESE_INDIA","AZERI_CYRILLIC",
            "AZERI_LATIN","BASHKIR_RUSSIA","BASQUE_BASQUE","BELARUSIAN_BELARUS","BANGLA_BANGLADESH",
            "BANGLA_INDIA","BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC","BOSNIAN_BOSNIA_HERZEGOVINA_LATIN",
            "BRETON_FRANCE","BULGARIAN_BULGARIA","CATALAN_CATALAN","CHINESE_HONGKONG","CHINESE_MACAU",
            "CHINESE_SIMPLIFIED","CHINESE_SINGAPORE","CHINESE_TRADITIONAL","CORSICAN_FRANCE",
            "CROATIAN_BOSNIA_HERZEGOVINA_LATIN","CROATIAN_CROATIA","CUSTOM_DEFAULT","CUSTOM_UNSPECIFIED",
            "CZECH_CZECH_REPUBLIC","DANISH_DENMARK","DARI_AFGHANISTAN","DEFAULT","DIVEHI_MALDIVES",
            "DUTCH_BELGIAN","DUTCH","ENGLISH_AUS","ENGLISH_BELIZE","ENGLISH_CAN","ENGLISH_CARIBBEAN",
            "ENGLISH_EIRE","ENGLISH_INDIA","ENGLISH_JAMAICA","ENGLISH_MALAYSIA","ENGLISH_NZ","ENGLISH_PHILIPPINES",
            "ENGLISH_SINGAPORE","ENGLISH_SOUTH_AFRICA","ENGLISH_TRINIDAD","ENGLISH_UK","ENGLISH_US",
            "ENGLISH_ZIMBABWE","ENGLISH_IRELAND","ESTONIAN_ESTONIA","FAEROESE_FAROE_ISLANDS","FILIPINO_PHILIPPINES",
            "FINNISH_FINLAND","FRENCH_BELGIAN","FRENCH_CANADIAN","FRENCH_LUXEMBOURG","FRENCH_MONACO",
            "FRENCH_SWISS","FRENCH","FRISIAN_NETHERLANDS","GALICIAN_GALICIAN","GEORGIAN_GEORGIA",
            "GERMAN_AUSTRIAN","GERMAN_LIECHTENSTEIN","GERMAN_LUXEMBOURG","GERMAN_SWISS","GERMAN",
            "GREEK_GREECE","GREENLANDIC_GREENLAND","GUJARATI_INDIA","HAUSA_NIGERIA_LATIN","HEBREW_ISRAEL",
            "HINDI_INDIA","HUNGARIAN_HUNGARY","ICELANDIC_ICELAND","IGBO_NIGERIA","INDONESIAN_INDONESIA",
            "INUKTITUT_CANADA_LATIN","INUKTITUT_CANADA","IRISH_IRELAND","ITALIAN_SWISS","ITALIAN",
            "JAPANESE_JAPAN","KANNADA_INDIA","KASHMIRI_INDIA","KASHMIRI_SASIA","KAZAK_KAZAKHSTAN",
            "KHMER_CAMBODIA","KICHE_GUATEMALA","KINYARWANDA_RWANDA","KONKANI_INDIA","KOREAN","KYRGYZ_KYRGYZSTAN",
            "LAO_LAO","LATVIAN_LATVIA","LITHUANIAN_CLASSIC","LITHUANIAN","LOWER_SORBIAN_GERMANY",
            "LUXEMBOURGISH_LUXEMBOURG","MACEDONIAN_MACEDONIA","MALAY_BRUNEI_DARUSSALAM","MALAY_MALAYSIA",
            "MALAYALAM_INDIA","MALTESE_MALTA","MAORI_NEW_ZEALAND","MAPUDUNGUN_CHILE","MARATHI_INDIA",
            "MOHAWK_MOHAWK","MONGOLIAN_CYRILLIC_MONGOLIA","MONGOLIAN_PRC","NEPALI_INDIA","NEPALI_NEPAL",
            "NEUTRAL","NORWEGIAN_BOKMAL","NORWEGIAN_NYNORSK","OCCITAN_FRANCE","ORIYA_INDIA","PASHTO_AFGHANISTAN",
            "PERSIAN_IRAN","POLISH_POLAND","PORTUGUESE_BRAZILIAN","PORTUGUESE","PUNJABI_INDIA",
            "QUECHUA_BOLIVIA","QUECHUA_ECUADOR","QUECHUA_PERU","ROMANIAN_ROMANIA","ROMANSH_SWITZERLAND",
            "RUSSIAN_RUSSIA","SAMI_INARI_FINLAND","SAMI_LULE_NORWAY","SAMI_LULE_SWEDEN","SAMI_NORTHERN_FINLAND",
            "SAMI_NORTHERN_NORWAY","SAMI_NORTHERN_SWEDEN","SAMI_SKOLT_FINLAND","SAMI_SOUTHERN_NORWAY",
            "SAMI_SOUTHERN_SWEDEN","SANSKRIT_INDIA","SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC","SERBIAN_BOSNIA_HERZEGOVINA_LATIN",
            "SERBIAN_CROATIA","SERBIAN_CYRILLIC","SERBIAN_LATIN","SINDHI_AFGHANISTAN","SINDHI_INDIA",
            "SINDHI_PAKISTAN","SINHALESE_SRI_LANKA","SLOVAK_SLOVAKIA","SLOVENIAN_SLOVENIA","SOTHO_NORTHERN_SOUTH_AFRICA",
            "SPANISH_ARGENTINA","SPANISH_BOLIVIA","SPANISH_CHILE","SPANISH_COLOMBIA","SPANISH_COSTA_RICA",
            "SPANISH_DOMINICAN_REPUBLIC","SPANISH_ECUADOR","SPANISH_EL_SALVADOR","SPANISH_GUATEMALA",
            "SPANISH_HONDURAS","SPANISH_MEXICAN","SPANISH_MODERN","SPANISH_NICARAGUA","SPANISH_PANAMA",
            "SPANISH_PARAGUAY","SPANISH_PERU","SPANISH_PUERTO_RICO","SPANISH_URUGUAY","SPANISH_US",
            "SPANISH_VENEZUELA","SPANISH","SWAHILI_KENYA","SWEDISH_FINLAND","SWEDISH","SYRIAC_SYRIA",
            "SYS_DEFAULT","TAJIK_TAJIKISTAN","TAMAZIGHT_ALGERIA_LATIN","TAMIL_INDIA","TATAR_RUSSIA",
            "TELUGU_INDIA","THAI_THAILAND","TIBETAN_PRC","TIGRIGNA_ERITREA","TSWANA_SOUTH_AFRICA",
            "TURKISH_TURKEY","TURKMEN_TURKMENISTAN","UI_CUSTOM_DEFAULT","UIGHUR_PRC","UKRAINIAN_UKRAINE",
            "UPPER_SORBIAN_GERMANY","URDU_INDIA","URDU_PAKISTAN","UZBEK_CYRILLIC","UZBEK_LATIN",
            "VIETNAMESE_VIETNAM","WELSH_UNITED_KINGDOM","WOLOF_SENEGAL","XHOSA_SOUTH_AFRICA",
            "YAKUT_RUSSIA","YI_PRC","YORUBA_NIGERIA","ZULU_SOUTH_AFRICA","PUNJABI_PAKISTAN",
            "TSWANA_BOTSWANA","TAMIL_SRI_LANKA","TIGRINYA_ETHIOPIA","TIGRINYA_ERITREA",
            "VALENCIAN_VALENCIA"]
        self.sublang_num = len(self.sublang_names)
        self.sublang_index = dict(zip(self.sublang_names, range(self.sublang_num)))
        self.fixed_dim = self.flags_num * 2 + self.os_num + self.type_num + self.subtype_num + 1 * 8
        self.version_dim = 1 * 2 + self.fixed_dim + 2 + 2
        self.icon_dim = self.lang_num +  self.sublang_num

    def name_strings(self):
        flag_names = ['DEBUG', 'INFOINFERRED', 'PATCHED', 'PRERELEASE', 'PRIVATEBUILD', 'SPECIALBUILD']
        fixed_names = ['signature', 'struct_version', 'file_version_MS', 'file_version_LS',
            'product_version_MS', 'product_version_LS'] + ['file_flags_mask:' + n for n in
            flag_names] + ['file_flags:' + n for n in flag_names] + ['file_os:' + n for n in
            self.os_names] + ['file_type:' + n for n in self.type_names] + ['file_subtype:' + n
            for n in self.subtype_names] + ['file_date_MS', 'file_date_LS']
        version_names = ['type', 'key'] + ['fixed_file_info:' + n for n in fixed_names] + [
            'string_file_info:type', 'string_file_info:key', 'var_file_info:type',
            'var_file_info:key']
        icon_names = ['lang:' + n for n in self.lang_names] + ['sublang:' + n for n in
        self.sublang_names]
        return ['version:' + n for n in version_names] + ['icons:' + n for n in icon_names] + [
            'num of icons', 'num of dialogs']

    def process_raw_features_from_fixed_file_info(self, raw_obj):
        if raw_obj is None:
            return np.zeros(self.fixed_dim)

        flags_mask = np.zeros(self.flags_num)
        flags = np.zeros(self.flags_num)
        raw_flags_mask = raw_obj['file_flags_mask']
        raw_flags = raw_obj['file_flags']
        for i in range(self.flags_num):
            if raw_flags_mask & self.flags_value[i] != 0:
                flags_mask[i] = 1
            if raw_flags & self.flags_value[i] != 0:
                flags[i] = 1
        os = np.zeros(self.os_num)
        os[self.os_index[raw_obj['file_os']]] = 1
        type = np.zeros(self.type_num)
        type[self.type_index[raw_obj['file_type']]] = 1
        subtype = np.zeros(self.subtype_num)
        subtype[self.subtype_index[raw_obj['file_subtype']]] = 1

        return np.hstack([
            raw_obj['signature'], raw_obj['struct_version'], raw_obj['file_version_MS'],
            raw_obj['file_version_LS'], raw_obj['product_version_MS'], raw_obj['product_version_LS'],
            flags_mask, flags, os, type, subtype, raw_obj['file_date_MS'], raw_obj['file_date_LS']
        ])

    def process_raw_features_from_string_file_info(self, raw_obj):
        if raw_obj is None:
            return np.zeros(2)

        return np.array([raw_obj['type'], int(raw_obj['key'] == "StringFileInfo")])

    def process_raw_features_from_var_file_info(self, raw_obj):
        if raw_obj is None:
            return np.zeros(2)

        return np.array([raw_obj['type'], int(raw_obj['key'] == "VarFileInfo")])

    def process_raw_features_from_version(self, raw_obj):
        if raw_obj is None:
            return np.zeros(self.version_dim)

        fixed = self.process_raw_features_from_fixed_file_info(raw_obj.get('fixed_file_info'))
        string = self.process_raw_features_from_string_file_info(raw_obj.get('string_file_info'))
        var = self.process_raw_features_from_var_file_info(raw_obj.get('var_file_info'))

        return np.hstack([
            raw_obj['type'], int(raw_obj['key'] == 'VS_VERSION_INFO'), fixed, string, var
        ])

    def process_raw_features_from_icons(self, raw_obj):
        lang = np.zeros(self.lang_num)
        sublang = np.zeros(self.sublang_num)
        for icon in raw_obj:
            lang[self.lang_index[icon['lang']]] += 1
            sublang[self.sublang_index[icon['sublang']]] += 1

        return np.hstack([lang, sublang])

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(self.version_dim + self.icon_dim + 1 * 2)
        version = self.process_raw_features_from_version(raw_obj.get('version'))
        raw_icon = raw_obj.get('icons', [])
        raw_dialog = raw_obj.get('dialogs', [])
        icons = self.process_raw_features_from_icons(raw_icon)
        return np.hstack([version, icons, len(raw_icon), len(raw_dialog)])

class Signature(FeatureType):
    name = 'signature'
    dim = 2

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return ['version', 'signer_info:version']

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(2)
        else:
            return np.array([raw_obj['version'], raw_obj['signer_info']['version']])

class Symbols(FeatureType):
    name = 'symbols'
    dim = 17 + 6 + 25

    def __init__(self):
        super(FeatureType, self).__init__()
        self.base_names = ["NULL", "VOID", "CHAR", "SHORT", "INT", "LONG", "FLOAT", "DOUBLE",
            "STRUCT", "UNION", "ENUM", "MOE", "BYTE", "WORD", "UINT", "DWORD", "Out of range"]
        self.base_num = len(self.base_names)
        self.base_index = dict(zip(self.base_names, range(self.base_num)))
        self.complex_names = ["NULL", "POINTER", "FUNCTION", "ARRAY", "COMPLEX_TYPE_SHIFT",
            "Out of range"]
        self.complex_num = len(self.complex_names)
        self.complex_index = dict(zip(self.complex_names, range(self.complex_num)))
        self.storage_names = ["END_OF_FUNCTION", "NULL", "AUTOMATIC", "EXTERNAL", "STATIC",
            "REGISTER", "EXTERNAL_DEF", "LABEL", "UNDEFINED_LABEL", "MEMBER_OF_STRUCT",
            "UNION_TAG", "TYPE_DEFINITION", "UDEFINED_STATIC", "ENUM_TAG", "MEMBER_OF_ENUM",
            "REGISTER_PARAM", "BIT_FIELD", "BLOCK", "FUNCTION", "END_OF_STRUCT", "FILE",
            "SECTION", "WEAK_EXTERNAL", "CLR_TOKEN", "Out of range"]
        self.storage_num = len(self.storage_names)
        self.storage_index = dict(zip(self.storage_names, range(self.storage_num)))

    def name_strings(self):
        return ['base_type:' + n for n in self.base_names] + ['complex_type:' + n for n in
            self.complex_names] + ['storage_class:' + n for n in self.storage_names]

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(self.dim)
        else:
            base_type = np.zeros(self.base_num)
            complex_type = np.zeros(self.complex_num)
            storage_class = np.zeros(self.storage_num)
            for symb in raw_obj:
                base_type[self.base_index[symb['base_type']]] += 1
                complex_type[self.complex_index[symb['complex_type']]] += 1
                storage_class[self.storage_index[symb['storage_class']]] += 1
            return np.hstack([base_type, complex_type, storage_class])

class LoadConfiguration(FeatureType):
    name = 'load_configuration'
    dim = 1 * 38 + 9 + 3 + 10 + 4

    def __init__(self):
        super(FeatureType, self).__init__()
        self.version_names = ['UNKNOWN', 'SEH', 'WIN_8_1', 'WIN10_0_9879', 'WIN10_0_14286',
            'WIN10_0_14383', 'WIN10_0_14901', 'WIN10_0_15002', 'WIN10_0_16237']
        self.version_num = len(self.version_names)
        self.version_index = dict(zip(self.version_names, range(self.version_num)))
        self.heap_values = [0x00040000, 0x00000004, 0x00000001]
        self.guard_values = [0x00000100, 0x00000200, 0x00000400, 0x00000800, 0x00001000,
            0x00002000, 0x00004000, 0x00008000, 0x00010000]
        self.integrity_names = ["flags", "catalog", "catalog_offset", "reserved"]

    def name_strings(self):
        heap_names = ["CREATE_ENABLE_EXECUTE", "GENERATE_EXCEPTIONS", "NO_SERIALIZE"]
        guard_names = ["CF_INSTRUMENTED", "CFW_INSTRUMENTED", "CF_FUNCTION_TABLE_PRESENT",
            "SECURITY_COOKIE_UNUSED", "PROTECT_DELAYLOAD_IAT", "DELAYLOAD_IAT_IN_ITS_OWN_SECTION",
            "CF_EXPORT_SUPPRESSION_INFO_PRESENT", "CF_ENABLE_EXPORT_SUPPRESSION",
            "CF_LONGJUMP_TABLE_PRESENT", "CF_FUNCTION_TABLE_SIZE"]
        return ['version:' + n for n in self.version_names] + ["characteristics", "timedatestamp",
            "major_version", "minor_version", "global_flags_clear", "global_flags_set",
            "critical_section_default_timeout", "decommit_free_block_threshold",
            "decommit_total_free_threshold", "lock_prefix_table", "maximum_allocation_size",
            "virtual_memory_threshold", "process_affinity_mask"] + ['process_heap_flags:' + n for
            n in heap_names] + ["csd_version", "reserved1", "editlist", "security_cookie",
            "se_handler_table", "se_handler_count", "guard_cf_check_function_pointer",
            "guard_cf_dispatch_function_pointer", "guard_cf_function_table",
            "guard_cf_function_count"] + ['guard_flags:' + n for n in guard_names] + [
            'code_integrity:' + n for n in self.integrity_names] + ["guard_address_taken_iat_entry_table",
            "guard_address_taken_iat_entry_count", "guard_long_jump_target_table",
            "guard_long_jump_target_count", "dynamic_value_reloc_table", "hybrid_metadata_pointer",
            "guard_rf_failure_routine", "guard_rf_failure_routine_function_pointer",
            "dynamic_value_reloctable_offset", "dynamic_value_reloctable_section", "reserved2",
            "guard_rf_verify_stackpointer_function_pointer", "hotpatch_table_offset", "reserved3",
            "addressof_unicode_string"]

    def process_raw_features(self, raw_obj):
        if raw_obj is None:
            return np.zeros(self.dim)
        version = np.zeros(self.version_num)
        version[self.version_index[raw_obj['version']]] = 1
        heap_flags = np.zeros(3)
        for i in range(3):
            if (raw_obj['process_heap_flags'] & self.heap_values[i]) != 0:
                heap_flags[i] = 1
        guard_flags = np.zeros(9)
        raw_gflag = raw_obj.get('guard_flags', 0)
        for i in range(9):
            if (raw_gflag & self.guard_values[i]) != 0:
                guard_flags[i] = 1
        cfg_stride = (raw_gflag & 0xF0000000) >> 28
        code_integrity = np.zeros(4)
        raw_integrity = raw_obj.get('code_integrity')
        if raw_integrity is not None:
            for i in range(4):
                code_integrity[i] = raw_integrity[self.integrity_names[i]]
        return np.hstack([
            version, raw_obj["characteristics"], raw_obj["timedatestamp"], raw_obj["major_version"],
            raw_obj["minor_version"], raw_obj["global_flags_clear"], raw_obj["global_flags_set"],
            raw_obj["critical_section_default_timeout"], raw_obj["decommit_free_block_threshold"],
            raw_obj["decommit_total_free_threshold"], raw_obj["lock_prefix_table"],
            raw_obj["maximum_allocation_size"], raw_obj["virtual_memory_threshold"],
            raw_obj["process_affinity_mask"], heap_flags, raw_obj["csd_version"], raw_obj["reserved1"],
            raw_obj["editlist"], raw_obj["security_cookie"], raw_obj.get("se_handler_table", 0),
            raw_obj.get("se_handler_count", 0), raw_obj.get("guard_cf_check_function_pointer", 0),
            raw_obj.get("guard_cf_dispatch_function_pointer", 0), raw_obj.get("guard_cf_function_table", 0),
            raw_obj.get("guard_cf_function_count", 0), guard_flags, cfg_stride, code_integrity,
            raw_obj.get("guard_address_taken_iat_entry_table", 0), raw_obj.get("guard_address_taken_iat_entry_count", 0),
            raw_obj.get("guard_long_jump_target_table", 0), raw_obj.get("guard_long_jump_target_count", 0),
            raw_obj.get("dynamic_value_reloc_table", 0), raw_obj.get("hybrid_metadata_pointer", 0),
            raw_obj.get("guard_rf_failure_routine", 0), raw_obj.get("guard_rf_failure_routine_function_pointer", 0),
            raw_obj.get("dynamic_value_reloctable_offset", 0), raw_obj.get("dynamic_value_reloctable_section", 0),
            raw_obj.get("reserved2", 0), raw_obj.get("guard_rf_verify_stackpointer_function_pointer", 0),
            raw_obj.get("hotpatch_table_offset", 0), raw_obj.get("reserved3", 0),
            raw_obj.get("addressof_unicode_string", 0)
        ])

class Extractor(object):

    def __init__(self):
        self.dim = sum([fe.dim for fe in self.features])

    def name_strings(self):
        l = []
        for fe in self.features:
            if fe.dim > 1:
                for n in fe.name_strings():
                    l.append(fe.name + ':' + n)
            else:
                l.append(fe.name_strings())
        return l

    def set_size(self, filesz, feature_name):
        for fe in self.features:
            if fe.name == feature_name:
                fe.set_size(filesz)

    def process_raw_features(self, raw_obj):
        feature_vectors = [fe.process_raw_features(raw_obj.get(fe.name)) for fe in self.features]
        return np.hstack(feature_vectors)

class LIEF(Extractor):
    name = 'lief'

    def __init__(self):
        self.features = [
            EntryPoint(),
            VirtualSize(),
            DOSHeader(),
            RichHeader(),
            Header(),
            OptionalHeader(),
            DataDirectories(),
            Sections(),
            Relocations(),
            Tls(),
            Export(),
            Debug(),
            Imports(),
            ResourcesTree(),
            ResourcesManager(),
            Signature(),
            Symbols(),
            LoadConfiguration()
        ]
        super(LIEF, self).__init__()

    def set_size(self, filesz):
        super(LIEF, self).set_size(filesz, 'optional_header')

class FileSize(FeatureType):
    name = 'file_size'
    dim = 1

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return self.name

    def process_raw_features(self, raw_obj):
        return raw_obj

class PEiD(FeatureType):
    name = 'peid'
    dim = 10

    def __init__(self):
        super(FeatureType, self).__init__()
        self.bit = {'32 bit': 0, '64 bit': 1}
        self.yes_no = {'no': 0, 'no (yes)': 1, 'yes': 2}

    def name_strings(self):
        return ['PE', 'DLL', 'Packed', 'Anti-Debug', 'GUI Program', 'Console Program', 'contains base64',
            'num of AntiDebug', 'num of PEiD', 'mutex']

    def process_raw_features(self, raw_obj):
        return np.array([self.bit[raw_obj['PE']], self.yes_no[raw_obj['DLL']], self.yes_no[raw_obj['Packed']],
            self.yes_no[raw_obj['Anti-Debug']], self.yes_no[raw_obj['GUI Program']], self.yes_no[raw_obj['Console Program']],
            self.yes_no[raw_obj['contains base64']], len(raw_obj['AntiDebug']), len(raw_obj['PEiD']),
            self.yes_no[raw_obj['mutex']]])

class Strings(FeatureType):
    name = 'strings'
    dim = 1 * 8 + 96

    def __init__(self):
        super(FeatureType, self).__init__()

    def name_strings(self):
        return ['num of strings', 'max_length', 'average_length', 'first_quartile', 'median', 'third quartile',
            'num of characters', 'probability of TAB'] + [f'probability of {chr(i)}' for i in range(32, 127)] \
            + ['entropy of characters']

    def process_raw_features(self, raw_obj):
        numstrings = len(raw_obj)
        if numstrings:
            string_lengths = np.array([len(s) for s in raw_obj])
            maxlength = np.nanmax(string_lengths)
            avlength = np.sum(string_lengths) / float(numstrings)
            q1, q2, q3 = np.percentile(string_lengths, [25, 50, 75])
            shifted_string = [0 if c == '\t' else ord(c) - ord(' ') + 1 for c in ''.join(raw_obj)]
            c = np.bincount(shifted_string, minlength=96)
            csum = c.sum()
            p = c.astype(float) / csum
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh]))
        else:
            maxlength = 0
            avlength = 0
            q1 = 0
            q2 = 0
            q3 = 0
            csum = 0
            p = np.zeros(96)
            H = 0.0

        return np.hstack([numstrings, maxlength, avlength, q1, q2, q3, csum, p, H])

class Hashes(FeatureType):
    name = 'hashes'
    dim = 106 + 32 + 102 + 70 + 40 + 40 + 40 + 32 + 40 + 64

    def __init__(self):
        super(FeatureType, self).__init__()
        self.names = ['ssdeep', 'imphash', 'impfuzzy', 'tlsh', 'totalhash', 'anymaster',
            'anymaster_v1_0_1', 'endgame', 'crits', 'pehashng']
        self.num = len(self.names)
        self.index = [0, 106, 138, 240, 310, 350, 390, 430, 462, 502]
        self.hlen = [106, 32, 102, 70, 40, 40, 40, 32, 40, 64]

    def name_strings(self):
        return [self.names[i] + '(' + str(j + 1) + ')' for i in range(self.num)
            for j in range(self.hlen[i])]

    def process_raw_features(self, raw_obj):
        hashes = np.zeros(self.dim)
        for i in range(self.num):
            data = raw_obj[self.names[i]]
            if data is None:
                data = ''
            for j in range(len(data)):
                hashes[self.index[i] + j] = ord(data[j]) - ord(' ')
        return hashes

class PEFeatureExtractor(Extractor):
    def __init__(self):
        self.features = [
            FileSize(),
            LIEF(),
            PEiD(),
            Strings(),
            Hashes()
        ]
        super(PEFeatureExtractor, self).__init__()

    def set_size(self, filesz):
        super(PEFeatureExtractor, self).set_size(filesz, 'lief')

    def process_raw_features(self, raw_obj):
        self.set_size(raw_obj['file_size'])
        return super(PEFeatureExtractor, self).process_raw_features(raw_obj)

class PackedFeatureExtractor(Extractor):
    def __init__(self):
        self.features = [
            FileSize(),
            LIEF(),
            Strings() #,
            #Hashes()
        ]
        super(PackedFeatureExtractor, self).__init__()

    def set_size(self, filesz):
        super(PackedFeatureExtractor, self).set_size(filesz, 'lief')

    def process_raw_features(self, raw_obj):
        self.set_size(raw_obj['file_size'])
        return super(PackedFeatureExtractor, self).process_raw_features(raw_obj)

class HeaderLIEF(Extractor):
    name = 'lief'

    def __init__(self):
        self.features = [
            Header(),
            OptionalHeader()
        ]
        super(HeaderLIEF, self).__init__()

    def set_size(self, filesz):
        super(HeaderLIEF, self).set_size(filesz, 'optional_header')

class PEHeaderExtractor(Extractor):
    def __init__(self):
        self.features = [
            HeaderLIEF()
        ]
        super(PEHeaderExtractor, self).__init__()

    def set_size(self, filesz):
        super(PEHeaderExtractor, self).set_size(filesz, 'lief')

    def process_raw_features(self, raw_obj):
        self.set_size(raw_obj['file_size'])
        return super(PEHeaderExtractor, self).process_raw_features(raw_obj)
