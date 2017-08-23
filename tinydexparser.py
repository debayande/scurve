import binascii
import mmap
import uuid

def uleb128_dec(g, offset):
    result, size = ord(g[offset]), 1
    if result > 0x7f:
        cur = ord(g[offset + 1])
        result = (result & 0x7f) | ((cur & 0x7f) << 7)
        size += 1
        if cur > 0x7f :
            cur = ord(g[offset + 2])
            result |= ((cur & 0x7f) << 14)
            size += 1
            if cur > 0x7f:
                cur = ord(g[offset + 3])
                result |= ((cur & 0x7f) << 21)
                size += 1
                if cur > 0x7f:
                    cur = ord(g[offset + 4])
                    result |= ((cur & 0x7f) << 28)
                    size += 1

    return result, size

class TinyParser:
    def __init__(self, path):
        f = open(path, "rb")
        f.seek(0x0, 0)
        self.magic            = binascii.b2a_hex(f.read(8))
        f.seek(0x8, 0)
        self.checksum        = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0xc, 0)
        self.signature       = binascii.b2a_hex(f.read(20))
        f.seek(0x20, 0)
        self.file_size       = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x24, 0)
        self.header_size     = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x28, 0)
        self.endian_tag      = binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex')
        f.seek(0x2c, 0)
        self.link_size       = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x30, 0)
        self.link_off        = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x34, 0)
        self.map_off         = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x38, 0)
        self.string_ids_size = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x3c, 0)
        self.string_ids_off  = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x40, 0)
        self.type_ids_size   = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x44, 0)
        self.type_ids_off    = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x48, 0)
        self.proto_ids_size  = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x4c, 0)
        self.proto_ids_off   = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x50, 0)
        self.field_ids_size  = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x54, 0)
        self.field_ids_off   = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x58, 0)
        self.method_ids_size = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x5c, 0)
        self.method_ids_off  = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x60, 0)
        self.class_defs_size = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x64, 0)
        self.class_defs_off  = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x68, 0)
        self.data_size       = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
        f.seek(0x6c, 0)
        self.data_off        = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)

        self.link_offsets = {}

        if self.link_size and self.link_off:
            ####
            #print "Links"
            #print self.data_off + self.data_size + self.link_off, self.data_off + self.data_size + self.link_off + self.link_size - 1
            self.link_offsets['links'] = (
                    self.data_off + self.data_size + self.link_off,
                    self.data_off + self.data_size + self.link_off + self.link_size - 1
            )

# ------------------------------------------------------------------------------

        self.class_defs_list = []

        for index in range(self.class_defs_size):
            f.seek(self.class_defs_off + 32 * index, 0)
            class_idx         = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            f.seek(self.class_defs_off + 32 * index + 4, 0)
            access_flags      = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            f.seek(self.class_defs_off + 32 * index + 8, 0)
            superclass_idx    = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            f.seek(self.class_defs_off + 32 * index + 12, 0)
            interfaces_off    = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            f.seek(self.class_defs_off + 32 * index + 16, 0)
            source_file_idx   = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            f.seek(self.class_defs_off + 32 * index + 20, 0)
            annotations_off   = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            f.seek(self.class_defs_off + 32 * index + 24, 0)
            class_data_off    = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            f.seek(self.class_defs_off + 32 * index + 28, 0)
            static_values_off = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            self.class_defs_list.append([class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off])

        self.annotation_offsets = {}

        for i, item in enumerate(self.class_defs_list):
            if item[5]:
                f.seek(item[5], 0)
                f.read(4)
                annotation_list_size = 16 + int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16) * 4 * 2
                annotation_list_size += int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16) * 4 * 2
                annotation_list_size += int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16) * 4 * 2
                ######
                #print 'Annotations'
                #print item[5], item[5] + annotation_list_size + 4 - 1
                self.annotation_offsets['annotation_' + str(uuid.uuid4())] = (item[5], item[5] + annotation_list_size + 4 - 1)

        self.class_data_offsets = {}

        for i, item in enumerate(self.class_defs_list):
            if item[6]:
                g, offset_clone = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ), item[6]
                static_fields_size, _ = uleb128_dec(g, offset_clone)
                offset_clone += _
                instance_fields_size, _ = uleb128_dec(g, offset_clone)
                offset_clone += _
                direct_methods_size, _ = uleb128_dec(g, offset_clone)
                offset_clone += _
                virtual_methods_size, _ = uleb128_dec(g, offset_clone)
                offset_clone += _
                for j in range(static_fields_size):
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                for j in range(instance_fields_size):
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                for j in range(direct_methods_size):
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    code_off = uleb128_dec(g, offset_clone)[0]
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    if code_off:
                        f.seek(code_off, 0)
                        f.read(12)
                        insns_size = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
                        #######
                        #print 'DM1'
                        # print code_off, code_off + 8 - 1
                        self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_aleph'] = (code_off, code_off + 8 - 1, [84, 39, 136])
                        #######
                        #print 'DM2'
                        #print code_off + 8, code_off + 8 + (2 * insns_size) - 1
                        self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_bet'] = (code_off + 8, code_off + 8 + (2 * insns_size) - 1, [153, 142, 195])
                        f.seek(code_off, 0)
                        f.read(6)
                        # padding, tries_size = 0, int(binascii.b2a_hex(f.read(2)).decode('hex')[::-1].encode('hex'), 16)
                        tries_size = int(binascii.b2a_hex(f.read(2)).decode('hex')[::-1].encode('hex'), 16)
                        if tries_size > 0:
                            if ((insns_size % 2) == 1):
                                padding = 2
                            else:
                                padding = 0
                                
                                ########
                                #print "DM3"
                            #print "j: ", j, code_off + 8 + (2 * insns_size) + padding, code_off + 8 + (2 * insns_size) + padding + (8 * tries_size) - 1
                            self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_gimel'] = (code_off + 8 + (2 * insns_size) + padding, code_off + 8 + (2 * insns_size) + padding + (8 * tries_size) - 1, [153, 142, 0])
                        f.seek(code_off, 0)
                        f.read(8)
                        debug_info_off = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
                        #noff = offset_clone
                        #if debug_info_off:
                            #noff += uleb128_dec(g, debug_info_off)[1]
                            #parameter_size = uleb128_dec(g, noff)[0]
                            #for j in range(parameter_size):
                                #noff += uleb128_dec(g, noff)[1]
                            #print "DM4"
                            #print debug_info_off, debug_info_off + (noff - debug_info_off) - 1
                        if debug_info_off:
                            koff = debug_info_off
                            koff += uleb128_dec(g, debug_info_off)[1]
                            parameter_size = uleb128_dec(g, koff)[0]
                            for j in range(parameter_size):
                                koff += uleb128_dec(g, koff)[1]
                            #print "DM4"
                            #print debug_info_off, debug_info_off + (koff - debug_info_off) - 1
                            self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_dalet'] = (debug_info_off, debug_info_off + (koff - debug_info_off) - 1, [255, 10, 235])

                for j in range(virtual_methods_size):
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    code_off = uleb128_dec(g, offset_clone)[0]
                    offset_clone += uleb128_dec(g, offset_clone)[1]
                    if code_off:
                        f.seek(code_off, 0)
                        f.read(12)
                        insns_size = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
                        #####
                        #print "VM1"
                        #print code_off, code_off + 8 - 1
                        self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_he'] = (code_off, code_off + 8 - 1, [179, 88, 6])
                        #####
                        #print "VM2"
                        #print code_off + 8, code_off + 8 + (2 * insns_size) - 1
                        self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_vav'] = (code_off + 8, code_off + 8 + (2 * insns_size) - 1, [241, 163, 64])
                        f.seek(code_off, 0)
                        f.read(6)
                        # padding, tries_size = 0, int(binascii.b2a_hex(f.read(2)).decode('hex')[::-1].encode('hex'), 16)
                        tries_size = int(binascii.b2a_hex(f.read(2)).decode('hex')[::-1].encode('hex'), 16)
                        if tries_size > 0:
                            if ((insns_size % 2) == 1):
                                padding = 2
                            else:
                                padding = 0
                                #####
                                #print "VM3"
                                #print code_off + 16 + (2 * insns_size) + padding, code_off + 16 + (2 * insns_size) + padding + (8 * tries_size) - 1
                            self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_zayin'] = (code_off + 16 + (2 * insns_size) + padding, code_off + 16 + (2 * insns_size) + padding + (8 * tries_size) - 1, [153, 142, 0])
                        f.seek(code_off, 0)
                        f.read(8)
                        debug_info_off = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
                        #if debug_info_off:
                            #offset_clone += uleb128_dec(g, debug_info_off)[1]
                            #parameter_size = uleb128_dec(g, offset_clone)[0]
                            #for j in range(parameter_size):
                                #offset_clone += uleb128_dec(g, offset_clone)[1]
                            ######
                            #print "VM4"
                            #print debug_info_off, debug_info_off + (offset_clone - debug_info_off) - 1
                            #self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_het'] = (debug_info_off, debug_info_off + (offset_clone - debug_info_off) - 1, [235, 0, 255])
                        if debug_info_off:
                            koff = debug_info_off
                            koff += uleb128_dec(g, debug_info_off)[1]
                            parameter_size = uleb128_dec(g, koff)[0]
                            for j in range(parameter_size):
                                koff += uleb128_dec(g, koff)[1]
                            #print "VM4"
                            #print debug_info_off, debug_info_off + (koff - debug_info_off) - 1
                            self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_het'] = (debug_info_off, debug_info_off + (koff - debug_info_off) - 1, [235, 0, 255])

                diff = offset_clone - item[6]
                #####
                #print "ENC1"
                #print item[6], item[6] + diff - 1
                self.class_data_offsets['class_data_' + str(uuid.uuid4()) + '_tet'] = (item[6], item[6] + diff - 1, [0, 150, 0])

        self.encoded_value_offsets = {}

        for i, item in enumerate(self.class_defs_list):
            if item[7]:
                g, offset_clone = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ), item[7]
                encoded_array_size, _ = uleb128_dec(g, offset_clone)
                offset_clone += _
                for j in range(encoded_array_size):
                    v = ord(g[offset_clone])
                    offset_clone += 1
                    offset_clone += ((v & 0o111) + 1)
                diff = offset_clone - item[7]
                #####
                #print "ENC2"
                #print item[7], item[7] + diff - 1
                self.encoded_value_offsets['encoded_values_' + str(uuid.uuid4())] = (item[7], item[7] + diff - 1)

        self.if_offsets = {}

        for i, item in enumerate(self.class_defs_list):
            if item[3]:
                f.seek(item[3], 0)
                interface_item_size = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
                #####
                #print "IFS"
                #print item[3], item[3] + (4 * interface_item_size) + 4 - 1
                self.if_offsets['class_ifs_' + str(uuid.uuid4())] = (item[3], item[3] + (4 * interface_item_size) + 4 - 1)

# ------------------------------------------------------------------------------

        self.map_offset = {}

        if self.map_off:
            f.seek(self.map_off, 0)
            mapsize = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            #####
            #print "MAP"
            #print self.map_off, self.map_off + (12 * mapsize + 4) - 1
            self.map_offset['dexmap'] = (
                self.map_off,
                self.map_off + (12 * mapsize + 4) - 1
            )

# ------------------------------------------------------------------------------

        self.proto_ids_list = []

        for index in range(self.proto_ids_size):
            f.seek(self.proto_ids_off + 12 * index, 0)
            shorty_idx      = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            return_type_idx = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            params_off      = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            self.proto_ids_list.append([shorty_idx, return_type_idx, params_off])

        self.proto_param_offsets = {}

        for i, item in enumerate(self.proto_ids_list):
            if item[2]:
                f.seek(item[2], 0)
                type_item_size = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
                ###
                #print "PPARAMS"
                #print item[2], item[2] + (4 * type_item_size + 4) - 1
                self.proto_param_offsets['proto_params_' + str(uuid.uuid4())] = (item[2], item[2] + (4 * type_item_size + 4) - 1)

# ------------------------------------------------------------------------------

        self.string_offsets = {}
        old = 0

        for index in range(self.string_ids_size):
            f.seek(self.string_ids_off + 4 * index, 0)
            string_data_off = int(binascii.b2a_hex(f.read(4)).decode('hex')[::-1].encode('hex'), 16)
            order = 1 if self.string_ids_off > old else 0
            old = self.string_ids_off

            g = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

            size = 1
            result = ord(g[string_data_off])
            if result > 0x7f:
                cur = ord(g[string_data_off + 1])
                result = (result & 0x7f) | ((cur & 0x7f) << 7)
                size += 1
                if cur > 0x7f :
                    cur = ord(g[string_data_off + 2])
                    result |= ((cur & 0x7f) << 14)
                    size += 1
                    if cur > 0x7f:
                        cur = ord(g[string_data_off + 3])
                        result |= ((cur & 0x7f) << 21)
                        size += 1
                        if cur > 0x7f:
                            cur = ord(g[string_data_off + 4])
                            result |= ((cur & 0x7f) << 28)
                            size += 1

            #####
            ##print "STR1"
            #print string_data_off, string_data_off + size - 1
            self.string_offsets['strings_' + str(uuid.uuid4()) + '_aleph'] = (string_data_off, string_data_off + size - 1, [240, 0, 0])
            #####
            #print "STR2"
            #print string_data_off + size, string_data_off + size + result - 1
            self.string_offsets['strings_' + str(uuid.uuid4()) + '_bet'] = (string_data_off + size, string_data_off + size + result - 1, [order * 100, 109, 44])

# ------------------------------------------------------------------------------

        self.rdict = {
            "class_defs": (
                self.class_defs_off,
                self.class_defs_off + (32 * self.class_defs_size) - 1
            ),
            "header": (
                0x0,
                self.header_size - 1
            ),
            "field_ids": (
                self.field_ids_off,
                self.field_ids_off + (8 * self.field_ids_size) - 1
            ),
            "proto_ids": (
                self.proto_ids_off,
                self.proto_ids_off + (12 * self.proto_ids_size) - 1
            ),
            "method_ids": (
                self.method_ids_off,
                self.method_ids_off + (8 * self.method_ids_size) - 1
            ),
            "string_ids": (
                self.string_ids_off,
                self.string_ids_off + (4 * self.string_ids_size) - 1
            ),
            "type_ids": (
                self.type_ids_off,
                self.type_ids_off + (4 * self.type_ids_size) - 1
            )
        }

        self.rdict.update(self.map_offset)
        self.rdict.update(self.proto_param_offsets)
        self.rdict.update(self.if_offsets)
        self.rdict.update(self.link_offsets)
        self.rdict.update(self.string_offsets)
        self.rdict.update(self.encoded_value_offsets)
        self.rdict.update(self.annotation_offsets)
        self.rdict.update(self.class_data_offsets)

    def get_offsets(self):
        return self.rdict
