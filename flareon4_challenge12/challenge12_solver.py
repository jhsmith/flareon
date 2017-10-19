#!/bin/env python
# Jay Smith (@jay_smif)
# Solver script for Flare-On 4 (2017) Challenge 12
# First run tcpflow on the given pcap to generate a set of TCP-stream files,
# two per TCP stream.
# Then run "python challenge12_solver.py <out_dir> <flow_dir>"
#   where <out_dir> is the directory to write output files to
#   and <flow_dir> is the directory containing tcpflow output files.

import os
import re
import cmd
import pdb
import sys
import time
import zlib
import base64
import string
import struct
import pprint
import hashlib
import logging
import binascii
import cStringIO
import traceback

# pip: hexdump
import hexdump

# pip: python-lzo
import lzo

# pip: xtea
import xtea

# pip: M2Crypto
import M2Crypto.RC4

# pip: pycrypto
import Crypto.Cipher.Blowfish
import Crypto.Cipher.XOR

#http://omake.accense.com/browser/camellia/trunk/pycamellia.py
import pycamellia

#https://github.com/snemes/kabopan/blob/master/kbp/comp/aplib.py
import kbp.comp.aplib as c_aplib

# we used vstruct heavily for declarative structures and parsing, and enums. quite nice
#https://github.com/vivisect/vivisect
import vstruct
from vstruct.primitives import *
import vstruct.defs.bmp as c_bmp
import vstruct.defs.win32 as c_win32

BITMAPFILEHEADER_SIZE = 0x0e
################################################################################
# stream constants
IMPLANT_TO_SERVER = 0
SERVER_TO_IMPLANT = 1

DirStrings = {
    IMPLANT_TO_SERVER : 'I2S',
    SERVER_TO_IMPLANT : 'S2I',
}

logger = logging.getLogger()
################################################################################

def getFdMd5(fd):
    pos = fd.tell()
    md = hashlib.md5(fd.read()).hexdigest()
    fd.seek(pos)
    return md

file_letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.'
def cleanFileName(name):
    #make sure only allowed characters are in the name, and ends with '_'
    return ''.join([ b if b in file_letters else '_' for b in name]) + '_'


################################################################################
class Report(object):
    '''
    Gathers parse data
    '''
    def __init__(self, odir):
        self.events = []
        self.odir = odir
        self.files = []

    def addEvent(self, etype, edata):
        self.events.append( (etype, edata) )

    def addFileFd(self, fd, name):
        md = getFdMd5(fd)
        cname = os.path.join(self.odir, '%s_%s' % (md, cleanFileName(name)))
        logger.debug('Adding file: %s', cname)
        with file(cname, 'wb') as ofile:
            ofile.write(fd.read())
        self.files.append( (md, name) )
        return md

    def addFileBytes(self, bytez, name):
        fd = cStringIO.StringIO()
        fd.write(bytez)
        fd.seek(0)
        ret = self.addFileFd(fd, name)
        fd.close()
        return ret

################################################################################
class TcpFlow(object):
    '''
    Stores the two sides to a TCP flow as file-objects
    '''
    def __init__(self, rpr, i2sFd, s2iFd):
        self.rpr = rpr
        self.fds = {}
        self.fds[IMPLANT_TO_SERVER] = i2sFd
        self.fds[SERVER_TO_IMPLANT] = s2iFd
        self.tastes = {}
        for k,v in self.fds.items():
            self.tastes[k] = v.read(1024)
            v.seek(0)

    def __repr__(self):
        return self.rpr

################################################################################



CRYPTO_HEADER_SIZE = 36
CMDSIG  = 0x20170417

CONNECT_TYPE = v_enum()
CONNECT_TYPE.UNKNOWN        = 0
CONNECT_TYPE.CLIENT         = 1
CONNECT_TYPE.SERVER         = 2

ERROR = v_enum()
ERROR.SUCCESS                   = 0
ERROR.BASE                      = 0x100000
ERROR.BAD_ARGUMENT              = (ERROR.BASE + 1)
ERROR.API_ERROR                 = (ERROR.BASE + 2)
ERROR.MISSING_PLUGIN            = (ERROR.BASE + 3)
ERROR.INTERRUPTED_ALLOC_PLUGIN  = (ERROR.BASE + 4)
ERROR.MALLOC                    = (ERROR.BASE + 5)
ERROR.LOAD_PLUGIN               = (ERROR.BASE + 6)
ERROR.NOT_AUTHENTICATED         = (ERROR.BASE + 7)

ERROR.SHELL_ERROR_BASE               = (ERROR.BASE + 0x1000)
ERROR.SHELL_NO_COMSPEC               = (ERROR.SHELL_ERROR_BASE + 1)
ERROR.SHELL_PIPE_ERROR               = (ERROR.SHELL_ERROR_BASE + 2)
ERROR.SHELL_CREATE_PROC_ERROR        = (ERROR.SHELL_ERROR_BASE + 3)
ERROR.SHELL_CREATE_THREAD_ERROR      = (ERROR.SHELL_ERROR_BASE + 4)
ERROR.SHELL_NOT_ACTIVE               = (ERROR.SHELL_ERROR_BASE + 5)
ERROR.SHELL_WRITE_ERROR              = (ERROR.SHELL_ERROR_BASE + 6)
ERROR.SHELL_READ_ERROR		     = (ERROR.SHELL_ERROR_BASE + 7)
ERROR.PROXY_ERROR_BASE		     = (ERROR.BASE + 0x2000)
ERROR.PROXY_CONN_CLOSED		     = (ERROR.PROXY_ERROR_BASE + 1)
ERROR.PROXY_ERROR_DISCONNECT	     = (ERROR.PROXY_ERROR_BASE + 2)
ERROR.FILE_ERROR_BASE		     = (ERROR.BASE + 0x3000)
ERROR.FILE_EXISTING_FILE_PUT_ERROR   = (ERROR.FILE_ERROR_BASE + 1)
ERROR.FILE_CREATE_ERROR		     = (ERROR.FILE_ERROR_BASE + 2)
ERROR.FILE_NOT_OPEN_ERROR	     = (ERROR.FILE_ERROR_BASE + 3)
ERROR.FILE_GUID_MISMATCH_ERROR	     = (ERROR.FILE_ERROR_BASE + 4)
ERROR.FILE_ADJUST_FILE_POINTER_ERROR = (ERROR.FILE_ERROR_BASE + 5)
ERROR.FILE_WRITE_ERROR		     = (ERROR.FILE_ERROR_BASE + 6)
ERROR.FILE_HASH_INCORRECT_ERROR	     = (ERROR.FILE_ERROR_BASE + 7)
ERROR.FILE_THREAD_ERROR		     = (ERROR.FILE_ERROR_BASE + 8)
ERROR.FILE_READ_ERROR		     = (ERROR.FILE_ERROR_BASE + 8)
ERROR.FILE_NO_SUCH_DIRECTORY_ERROR   = (ERROR.FILE_ERROR_BASE + 9)
ERROR.SCREEN_ERROR_BASE		     = (ERROR.BASE + 0x4000)
ERROR.SCREEN_GETDIBITS_ERROR	     = (ERROR.SCREEN_ERROR_BASE + 1)


SHELLCMD = v_enum()
SHELLCMD.BASE           = 0
SHELLCMD.ACTIVATE       = (SHELLCMD.BASE + 1)
SHELLCMD.DEACTIVATE     = (SHELLCMD.BASE + 2)
SHELLCMD.SHELLIN        = (SHELLCMD.BASE + 3)
SHELLCMD.SHELLOUT       = (SHELLCMD.BASE + 4)

SCREENCMD = v_enum()
SCREENCMD.SCREEN_CMD_BASE       = 0
SCREENCMD.SCREEN_SCREENSHOT     = (SCREENCMD.SCREEN_CMD_BASE + 1)
SCREENCMD.SCREEN_BITMAPINFO     = (SCREENCMD.SCREEN_CMD_BASE + 2)
SCREENCMD.SCREEN_BITMAPDATA     = (SCREENCMD.SCREEN_CMD_BASE + 3)

MAINC2CMD = v_enum()
MAINC2CMD.BASE              = 0
MAINC2CMD.HEARTBEAT         = (MAINC2CMD.BASE + 1)
MAINC2CMD.PING              = (MAINC2CMD.BASE + 2)
MAINC2CMD.HOSTINFO          = (MAINC2CMD.BASE + 3)
MAINC2CMD.QUERYPLUGINS      = (MAINC2CMD.BASE + 4)
MAINC2CMD.ALLOCPLUGIN       = (MAINC2CMD.BASE + 5)
MAINC2CMD.ADDPLUGINDATA     = (MAINC2CMD.BASE + 6)
MAINC2CMD.LOADPLUGIN        = (MAINC2CMD.BASE + 7)
MAINC2CMD.EXIT              = (MAINC2CMD.BASE + 8)
MAINC2CMD.GETCONFIG         = (MAINC2CMD.BASE + 9)
MAINC2CMD.SETCONFIG         = (MAINC2CMD.BASE + 10)
MAINC2CMD.MSGBOX            = (MAINC2CMD.BASE + 11)
MAINC2CMD.DISCONNECT        = (MAINC2CMD.BASE + 12)
MAINC2CMD.CANCELLOADPLUGIN  = (MAINC2CMD.BASE + 13)
MAINC2CMD.AUTHENTICATE      = (MAINC2CMD.BASE + 14)

FILECMD = v_enum()
FILECMD.BASE                = 0
FILECMD.DRIVE_LIST          = (FILECMD.BASE + 1)
FILECMD.DIR_LIST            = (FILECMD.BASE + 2)
FILECMD.FILE_GET            = (FILECMD.BASE + 3)
FILECMD.FILE_GET_DATA       = (FILECMD.BASE + 4)
FILECMD.FILE_GET_DONE       = (FILECMD.BASE + 5)
FILECMD.FILE_PUT            = (FILECMD.BASE + 6)
FILECMD.FILE_PUT_DATA       = (FILECMD.BASE + 7)
FILECMD.CREATE_DIR          = (FILECMD.BASE + 8)
FILECMD.DEL_FILE            = (FILECMD.BASE + 9)
FILECMD.DEL_DIR             = (FILECMD.BASE + 10)


PROXYCMD = v_enum()
PROXYCMD.CMD_BASE           = 0
PROXYCMD.CONNECT            = (PROXYCMD.CMD_BASE + 1)
PROXYCMD.DISCONNECT         = (PROXYCMD.CMD_BASE + 2)
PROXYCMD.DATA               = (PROXYCMD.CMD_BASE + 3)
PROXYCMD.QUERY_CONNECTIONS  = (PROXYCMD.CMD_BASE + 4)


NullCryptoPluginGuidBytes           = '51298F741667D7ED2941950106F50545'.decode('hex')
Rc4CryptoPluginGuidBytes            = 'c30b1a2dcb489ca8a724376469cf6782'.decode('hex')
LookupTableCryptoPluginGuidBytes    = '38be0f624ce274fc61f75c90cb3f5915'.decode('hex')
CustomBase64CryptoPluginGuidBytes   = 'ba0504fcc08f9121d16fd3fed1710e60'.decode('hex')
XteaCryptoPluginGuidBytes           = 'b2e5490d2654059bbbab7f2a67fe5ff4'.decode('hex')
BlowfishCryptoPluginGuidBytes       = '2965e4a19b6e9d9473f5f54dfef93533'.decode('hex')
SimpleXorCryptoPluginGuidBytes      = '8746e7b7b0c1b9cf3f11ecae78a3a4bc'.decode('hex')
Des3CryptoPluginGuidBytes           = '46c5525904f473ace7bb8cb58b29968a'.decode('hex')
CamelliaCryptoPluginGuidBytes       = '9b1f6ec7d9b42bf7758a094a2186986b'.decode('hex')
NullCompressPluginGuidBytes         = 'f37126ad88a5617eaf06000d424c5a21'.decode('hex')
ZlibCompressPluginGuidBytes         = '5fd8ea0e9d0a92cbe425109690ce7da2'.decode('hex')
LzoCompressPluginGuidBytes          = '0a7874d2478a7713705e13dd9b31a6b1'.decode('hex')
ApLibCompressPluginGuidBytes        = '503b6412c75a7c7558d1c92683225449'.decode('hex')
MainC2CommandPluginGuidBytes        = '155bbf4a1efe1517734604b9d42b80e8'.decode('hex')
FileCommandPluginGuidBytes          = 'f47c51070fa8698064b65b3b6e7d30c6'.decode('hex')
ShellCommandPluginGuidBytes         = 'f46d09704b40275fb33790a362762e56'.decode('hex')
ProxyCommandPluginGuidBytes         = '77d6ce92347337aeb14510807ee9d7be'.decode('hex')
ScreenCommandPluginGuidBytes        = 'a3aecca1cb4faa7a9a594d138a1bfbd5'.decode('hex')

PLUGIN_NAMES = {
    NullCryptoPluginGuidBytes            : 'NullCrypto',
    Rc4CryptoPluginGuidBytes             : 'Rc4Crypto',
    LookupTableCryptoPluginGuidBytes     : 'LookupTableCrypto',
    CustomBase64CryptoPluginGuidBytes    : 'CustomBase64Crypto',
    XteaCryptoPluginGuidBytes            : 'XteaCrypto',
    BlowfishCryptoPluginGuidBytes        : 'BlowfishCrypto',
    SimpleXorCryptoPluginGuidBytes       : 'SimpleXorCrypto',
    Des3CryptoPluginGuidBytes            : 'Des3Crypto',
    CamelliaCryptoPluginGuidBytes        : 'CamelliaCrypto',
    NullCompressPluginGuidBytes          : 'NullCompress',
    ZlibCompressPluginGuidBytes          : 'ZlibCompress',
    LzoCompressPluginGuidBytes           : 'LzoCompress',
    ApLibCompressPluginGuidBytes         : 'ApLibCompress',
    MainC2CommandPluginGuidBytes         : 'MainC2Command',
    FileCommandPluginGuidBytes           : 'FileComamnd',
    ShellCommandPluginGuidBytes          : 'ShellCommand',
    ProxyCommandPluginGuidBytes          : 'ProxyCommand',
    ScreenCommandPluginGuidBytes         : 'ScreenCommand',
}
CMD_PLUGIN_ENUMS = {
    MainC2CommandPluginGuidBytes        : MAINC2CMD, 
    FileCommandPluginGuidBytes          : FILECMD,
    ShellCommandPluginGuidBytes         : SHELLCMD,
    ProxyCommandPluginGuidBytes         : PROXYCMD,
    ScreenCommandPluginGuidBytes        : SCREENCMD,
}

g_LookupTable = [
    199, 25, 48, 12, 168, 16, 173, 213, 212, 22, 82, 252, 27, 130, 125, 
    50, 52, 1, 230, 76, 18, 8, 43, 247, 172, 139, 63, 103, 72, 114, 33, 
    220, 237, 246, 133, 184, 79, 95, 83, 10, 4, 40, 223, 216, 126, 6, 
    61, 3, 64, 54, 104, 115, 37, 183, 93, 30, 210, 13, 198, 195, 34, 242, 
    32, 14, 23, 204, 96, 92, 81, 194, 29, 74, 203, 51, 28, 248, 102, 131, 
    107, 62, 39, 227, 159, 245, 58, 170, 138, 38, 127, 90, 66, 207, 124, 
    7, 88, 113, 235, 5, 186, 41, 75, 122, 224, 236, 154, 123, 46, 55, 254,
    164, 190, 73, 222, 0, 197, 187, 150, 233, 196, 121, 153, 135, 244, 19, 
    26, 21, 99, 249, 160, 209, 2, 214, 9, 31, 229, 146, 106, 231, 24, 67, 
    145, 110, 65, 200, 163, 178, 44, 238, 141, 166, 91, 239, 36, 185, 117, 
    87, 15, 111, 17, 71, 155, 59, 118, 225, 157, 100, 84, 167, 193, 85, 
    179, 137, 49, 253, 171, 177, 148, 182, 20, 47, 243, 188, 105, 191, 
    161, 128, 89, 11, 189, 201, 42, 215, 129, 60, 35, 211, 241, 250, 234, 
    57, 56, 158, 94, 181, 69, 97, 255, 78, 119, 77, 101, 156, 232, 217, 
    147, 175, 80, 162, 132, 136, 120, 152, 226, 134, 206, 221, 140, 142, 
    169, 149, 112, 174, 228, 202, 98, 205, 144, 192, 251, 176, 219, 180, 
    208, 151, 240, 45, 70, 218, 108, 109, 68, 116, 165, 143, 86, 53
]


class CompressHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.headerSize = v_uint32()
        self.dataEncSize = v_uint32()
        self.dataDecSize = v_uint32()
        self.guid = v_bytes(16)

class CryptoHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.sig = v_bytes(4)
        self.crc = v_uint32()
        self.headerSize = v_uint32()
        self.dataEncSize = v_uint32()
        self.dataDecSize = v_uint32()
        self.guid = v_bytes(16)

class Rc4CryptoHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.head = CryptoHeader()
        self.key = v_bytes(16)

class SimpleXorCryptoHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.head = CryptoHeader()
        self.key = v_bytes(4)

class BlowfishCryptoHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.head = CryptoHeader()
        self.key = v_bytes(16)
        self.iv = v_bytes(8)

class Des3CryptoHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.head = CryptoHeader()
        self.key = v_bytes(24)
        self.iv = v_bytes(8)

class CamelliaCryptoHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.head = CryptoHeader()
        self.key = v_bytes(16)


class XteaCryptoHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.head = CryptoHeader()
        self.key = v_bytes(16)
        self.iv = v_bytes(8)

class CommandHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.sig                = v_uint32()
        self.command            = v_uint32()
        self.msgId              = v_uint32()
        self.status             = v_uint32()
        self.extendedStatus     = v_uint32()
        self.guid               = v_bytes(16)

class AddPluginDataResp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead              = CommandHeader()
        self.guid               = v_bytes(16)
        self.type               = v_uint32()
        self.offset             = v_uint32()
        self.totalsize          = v_uint32()
        self.chunksize          = v_uint32()

class DirListCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead              = CommandHeader()
        self.directory          = v_wstr(260)

class DriveListItem(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.driveName          = v_wstr(4)
        self.drivetype          = v_uint32()
        self.volSerialNumber    = v_uint32()
        self.totalBytes         = v_uint64()
        self.userFreeBytes      = v_uint64()
        self.freeBytes          = v_uint64()
        self.volumeName         = v_wstr(128)
        self.volumeType         = v_wstr(128)


PLUGIN_TYPES = v_enum()
PLUGIN_TYPES.Command            = 0x20444d43
PLUGIN_TYPES.Crypto             = 0x54505243
PLUGIN_TYPES.Compression        = 0x504d4f43

class QueryPluginsItem(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.guid = v_bytes(16)
        self.plugtype           = v_uint32(enum=PLUGIN_TYPES)
        self.name               = v_str(64)
        self.version            = v_str(64)

class HostInfoResp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.hostid                 = v_bytes(16)
        self.version                = v_str(64)
        self.computername           = v_wstr(64)
        self.username               = v_wstr(64)
        self.memo                   = v_wstr(256)
        self.isAdmin                = v_uint32()
        self.connectType            = v_uint32(enum=CONNECT_TYPE)
        self.defaultLcid            = v_uint32()
        self.osVersionMajor         = v_uint32()
        self.osVersionMinor         = v_uint32()
        self.osVersionBuild         = v_uint32()
        self.osVersionPlatformId    = v_uint32()

class ProxyConnectCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.port                   = v_uint32()
        self.hostname               = v_str(256)

class ProxyQueryItem(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.index                  = v_uint32()
        self.runFlag                = v_uint32()
        self.port                   = v_uint32()
        self.hostname               = v_str(256)

class FileGetDataResp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.guid                   = v_bytes(16)
        self.offset                 = v_uint64()
        self.totalLen               = v_uint64()
        self.length                 = v_uint64()
        self.data                   = v_bytes()

    def pcb_length(self):
        self.vsGetField('data').vsSetLength(self.length)

class BitmapInfoResp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.length                 = v_uint32()
        self.data                   = v_bytes()

    def pcb_length(self):
        self.vsGetField('data').vsSetLength(self.length)

class AuthenticateCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead              = CommandHeader()
        self.password           = v_zwstr()

class AddPluginDataCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead              = CommandHeader()
        self.guid               = v_bytes(16)
        self.pluginType         = v_uint32()
        self.offset             = v_uint32()
        self.totalFileLen       = v_uint32()
        self.chunkLen           = v_uint32()
        self.chunk              = v_bytes()

    def pcb_chunkLen(self):
        self.vsGetField('chunk').vsSetLength(self.chunkLen)

class BitmapDataResp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.offset                 = v_uint32()
        self.totalLength            = v_uint32()
        self.length                 = v_uint32()
        self.data                   = v_bytes()

    def pcb_length(self):
        self.vsGetField('data').vsSetLength(self.length)


class FilePutCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.guid                   = v_bytes(16)
        self.offset                 = v_uint64()
        self.totalLen               = v_uint64()
        self.sha1sum                = v_bytes(20)
        self.filename               = v_wstr(256)

class FilePutData(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.guid                   = v_bytes(16)
        self.offset                 = v_uint64()
        self.totalLen               = v_uint64()
        self.length                 = v_uint64()
        self.data                   = v_bytes()

    def pcb_length(self):
        self.vsGetField('data').vsSetLength(self.length)

class FileGetCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.guid                   = v_bytes(16)
        self.filename               = v_wstr(256)

class ProxyQueryItem(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.index                  = v_uint32()
        self.runFlag                = v_uint32()
        self.port                   = v_uint32()
        self.hostname               = v_str(256)

################################################################################
def decodeSecondStage(inBytes):
    key = struct.unpack_from('<I', inBytes)[0]
    v0 = v1 =  v2 = v3 = key
    result =  []
    for i in xrange(len(inBytes) - 4):
        v0 = 0xffffffff & (v0 + ((v0 >> 3) + 0x22334455))
        v1 = 0xffffffff & (v1 + ((v1 >> 5) + 0x11223344))
        v2 = 0xffffffff & (-127 * v2  + 0x44556677)
        v3 = 0xffffffff & (-511 * v3  + 0x33445566)
        b =  0xff & (v3 + v2 + v1 + v0) ^ ord(inBytes[i+4])
        result.append(chr(b))
    return ''.join(result)


################################################################################

class FileTransferChunk(object):
    def __init__(self, filename, guid, totalSize):
        self.filename = filename
        self.guid = guid
        self.totalSize = totalSize
        self.currentSize = 0
        self.data = []
    
    def addData(self, data, offset):
        if offset != self.currentSize:
            logger.info('addData out of order: offset 0x%08x, expected 0x%08x', offset, self.currentSize)
            raise RuntimeError('Out of order file chunk')
        self.data.append(data)
        self.currentSize += len(data)

    def isComplete(self):
        return self.currentSize == self.totalSize

    def getFd(self):
        fd = cStringIO.StringIO()
        for dat in self.data:
            fd.write(dat)
        fd.seek(0)
        return fd


################################################################################

class MalarkeyParser(object):
    def __init__(self, flow, report):
        self.flow = flow
        self.report = report

        self.newAlph  = 'B7wAOjbXLsD+S24/tcgHYqFRdVKTp0ixlGIMCf8zvE5eoN1uyU93Wm6rZPQaJhkn'
        self.origAlph = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        self.b64DecryptTable = string.maketrans(self.newAlph, self.origAlph)

        self.bminfo = None
        self.bitmapdata = None
        self.bmpStruct = vstruct.defs.bmp.BITMAPINFOHEADER()
        self.proxyConns = {}
        self.proxyConnects = {}
        self.proxyConnectResps = {}
        self.files = {}
        self.fileGetCmds = {}

    def getBitmapFileHeader(self):
        bfSize = BITMAPFILEHEADER_SIZE + self.bmpStruct.biSize + (self.bmpStruct.biClrUser * 4) + self.bmpStruct.biSizeImage
        bitsOffset = BITMAPFILEHEADER_SIZE + self.bmpStruct.biSize + (self.bmpStruct.biClrUser * 4) 
        return struct.pack('<HIHHI', 0x4d42, bfSize, 0, 0, bitsOffset)

    def parse(self):
        try:
            logger.debug('Starting flow: %r', self.flow)
            self.parseBinaryStream(SERVER_TO_IMPLANT, self.flow.fds[SERVER_TO_IMPLANT])
            self.parseBinaryStream(IMPLANT_TO_SERVER, self.flow.fds[IMPLANT_TO_SERVER])
            self.finishParse()
        except Exception, err:
            logger.exception('Error during parse: %s', str(err))

    def finishParse(self):
        for connid, conn in self.proxyConns.items():
            srvip = None
            srvport = None
            conn[IMPLANT_TO_SERVER].seek(0)
            conn[SERVER_TO_IMPLANT].seek(0)

            connMsgId = self.proxyConnectResps.get(connid)
            if connMsgId is not None:
                tup = self.proxyConnects.get(connMsgId)
                if tup is not None:
                    srvip, srvport = tup
                else:
                    logger.warning('Missing proxyConnect for conn 0x%x', connid, connMsgId)
            else:
                logger.warning('Missing proxyConnectResps for conn 0x%x', connid)
            if srvip is None:
                logger.warning('Missing proxy destination')
            else:
                self.report.addEvent('proxy_connect', dict(remote_host=srvip, remote_port=srvport))

                rpr = self.flow.rpr + '-%s:%d' % (srvip, srvport)
                iflow = TcpFlow(rpr, conn[IMPLANT_TO_SERVER], conn[SERVER_TO_IMPLANT])
                logger.debug('Parsing proxy flow')    
                parseFlow(self.report, iflow)
            conn[SERVER_TO_IMPLANT].close()
            conn[IMPLANT_TO_SERVER].close()

    def decompress(self, idata):
        comphead = CompressHeader()
        off = comphead.vsParse(idata)
        funcname = 'do_decompress_%s' % PLUGIN_NAMES.get(comphead.guid, 'UNKNOWN')
        func = getattr(self, funcname, None)
        if func is None:
            logger.warning('No compression function implementation: %s: %s', funcname, comphead.guid.encode('hex'))
            return None
        #logger.debug('Dispatching decompress %s', funcname)
        return func(comphead, idata[comphead.headerSize:comphead.headerSize+comphead.dataEncSize])
    
    def do_decompress_NullCompress(self, comphead, idata):
        return idata

    def do_decompress_ZlibCompress(self, comphead, idata):
        ret =  zlib.decompress(idata)
        if len(ret) != comphead.dataDecSize:
            raise RuntimeError('Weird zlib return')
        return ret

    def do_decompress_ApLibCompress(self, comphead, idata):
        decData, decLength = c_aplib.decompress(idata[24:]).do()
        return decData

    def do_decompress_LzoCompress(self, comphead, idata):
        # python-lzo uses a custom header of '>BI' -> 0xf0, decompressedLen
        t2 = struct.pack('>BI', 0xf0, comphead.dataDecSize) + idata
        return lzo.decompress(t2)

    def decrypt(self, crypthead, chead, encData):
        funcname = 'do_decrypt_%s' % PLUGIN_NAMES.get(crypthead.guid, 'UNKNOWN')
        func = getattr(self, funcname, None)
        if func is None:
            logger.warning('No crypto function implementation: %s', funcname)
            return None
        #logger.debug('Dispatching decrypt: %s', funcname)
        compData = func(crypthead, chead, encData)
        if compData is None:
            logger.warning('Crypto failed %s', funcname)
            return None
        return self.decompress(compData)

    def do_decrypt_NullCrypto(self, crypthead, chead, encData):
        return encData 

    def do_decrypt_XteaCrypto(self, crypthead, chead, encData):
        xteaHead = XteaCryptoHeader()
        xteaHead.vsParse(chead)

        tea = xtea.new(xteaHead.key, mode=xtea.MODE_CBC, IV=xteaHead.iv)
        outBytes = tea.decrypt(encData)
        return outBytes[:xteaHead.head.dataDecSize]

    def do_decrypt_CustomBase64Crypto(self, crypthead, chead, encData):
        xlateBytes = encData[:crypthead.dataEncSize].translate(self.b64DecryptTable)
        return base64.b64decode(xlateBytes)

    def do_decrypt_LookupTableCrypto(self, crypthead, chead, encData):
        retList = []
        for i in encData:
            retList.append(chr(g_LookupTable[ord(i)]))
        return ''.join(retList)

    def do_decrypt_SimpleXorCrypto(self, crypthead, chead, encData):
        xorHead = SimpleXorCryptoHeader()
        if len(xorHead) != len(chead):
            raise RuntimeError('Bad xor header')
        xorHead.vsParse(chead)
        cxor = Crypto.Cipher.XOR.new(xorHead.key)
        return cxor.decrypt(encData)[:xorHead.head.dataDecSize]

    def do_decrypt_BlowfishCrypto(self, crypthead, chead, encData):
        blowHead = BlowfishCryptoHeader()
        if len(blowHead) != len(chead):
            logger.warning('Bad blowfish header: 0x%x vs 0x%x', len(blowHead), len(chead))
            hexdump.hexdump(chead)
            raise RuntimeError('Bad blowfish header')
        blowHead.vsParse(chead)
        bf = Crypto.Cipher.Blowfish.new(blowHead.key, Crypto.Cipher.Blowfish.MODE_CBC, blowHead.iv)
        outBytes = bf.decrypt(encData[:blowHead.head.dataEncSize])
        return outBytes[:blowHead.head.dataDecSize]

    def do_decrypt_Rc4Crypto(self, crypthead, chead, encData):
        rc4Head = Rc4CryptoHeader()
        rc4Head.vsParse(chead)
        rc = M2Crypto.RC4.RC4(rc4Head.key)
        outdata = rc.update(encData)
        return outdata

    def do_decrypt_Des3Crypto(self, crypthead, chead, encData):
        deshead = Des3CryptoHeader()
        deshead.vsParse(chead)
        evp = M2Crypto.EVP.Cipher(alg='des_ede3_cbc', iv=deshead.iv, key=deshead.key, op=0, padding=0)
        outBytes = evp.update(encData) + evp.final()
        return outBytes[:crypthead.dataDecSize]

    def do_decrypt_CamelliaCrypto(self, crypthead, chead, encData):
        camHead = CamelliaCryptoHeader()
        camHead.vsParse(chead)
        camkey = pycamellia.Ekeygen(camHead.key)
        outArr = [] 
        for i in range(camHead.head.dataEncSize/16):
            outArr.append(pycamellia.DecryptBlock(encData[16*i:16*i+16], camkey))
        outBytes = ''.join(outArr) 
        return outBytes[:crypthead.dataDecSize]

    def parseBinaryStream(self, dir, fd):
        logger.debug('parseBinaryStream %s', DirStrings[dir])
        try:
            crypthead = CryptoHeader()
            off = fd.tell()
            chead = fd.read(len(crypthead))
            while len(chead) == len(crypthead):
                #logger.debug('Working at off 0x%08x', off)
                crypthead.vsParse(chead)
                if crypthead.sig != '2017':
                    raise RuntimeError('Missing 2017 sig')
                if len(chead) < crypthead.headerSize:
                    chead = chead + fd.read(crypthead.headerSize - len(chead))
                if len(chead) != crypthead.headerSize:
                    raise RuntimeError('Bad header size now :(')
                encData = fd.read(crypthead.dataEncSize)
                if len(encData) != crypthead.dataEncSize:
                    raise RuntimeError('Short read')
                #logger.debug('Trying to decrypt:%s', crypthead.tree())
                #hexdump.hexdump(encData[:0x100])
                data = self.decrypt(crypthead, chead, encData)
                if data is None:
                    logger.debug('Stopping early due to empty decrypt')
                    break
                crc32 = binascii.crc32(data) & 0xffffffff
                if crc32 != crypthead.crc:
                    raise RuntimeError('Bad crc32 after decrypt/decompress')
                #logger.warning('Unhandled %s data:', DirStrings[dir])
                #hexdump.hexdump(data)
                try:
                    self.dispatchPayload(dir, data)
                except Exception, err:
                    logger.exception('Error during dispatch: %s', str(err))
                off = fd.tell()
                chead = fd.read(len(crypthead))
        except Exception, err:
            logger.exception('Error during parse: %s', str(err))

    def dispatchPayload(self, dir, data):
        cmdHeader = CommandHeader()
        if len(data) < len(cmdHeader):
            raise RuntimeError('Bad command header: too small')
        off = cmdHeader.vsParse(data)
        if cmdHeader.sig != CMDSIG:
            logger.warning('0x%08x vs 0x%08x', cmdHeader.sig, CMDSIG)
            hexdump.hexdump(data)
            raise RuntimeError('Bad command header: missing sig')
        pluginName =  PLUGIN_NAMES.get(cmdHeader.guid, None)
        if pluginName is None:
            raise RuntimeError('Unknown command guid')
        cmdName = CMD_PLUGIN_ENUMS[cmdHeader.guid].vsReverseMapping(cmdHeader.command)
        funcname = 'do_%s_%s_%s' % (DirStrings[dir], pluginName, cmdName)
        func = getattr(self, funcname, None)
        if func is None:
            logger.warning('No command function implementation: %s', funcname)
            hexdump.hexdump(data)
            return None
        logger.debug('Dispatching command %s', funcname)
        return func(dir, data, cmdHeader)

    def do_I2S_MainC2Command_AUTHENTICATE(self, dir, data, cmdHeader):
        if cmdHeader.status == 0:
            logger.debug('I2S_MainC2Command_AUTHENTICATE: Success')
        else:
            logger.debug('I2S_MainC2Command_AUTHENTICATE: Failure')

    def do_I2S_MainC2Command_QUERYPLUGINS(self, dir, data, cmdHeader):
        off = len(cmdHeader)
        i = 0
        item = QueryPluginsItem()
        if cmdHeader.status != 0:
            logger.info('I2S_MainC2Command_QUERYPLUGINS: error 0x%08x 0x%08x', cmdHeader.status, cmdHeader.extendedStatus)
            return
        ret = []
        logger.debug('I2S_MainC2Command_QUERYPLUGINS: %d items', cmdHeader.extendedStatus)
        while (i < cmdHeader.extendedStatus) and (off<len(data)):
            off = item.vsParse(data, off)
            logger.debug('%s', item.tree())
            ret.append('  %02d:%s:%4s:%11s:%s' % (i, item.guid.encode('hex'), item.version, PLUGIN_TYPES.vsReverseMapping(item.plugtype), PLUGIN_NAMES.get(item.guid, 'UNKNOWN')))
            logger.debug('  %02d:%s:%4s:%11s:%s', i, item.guid.encode('hex'), item.version, PLUGIN_TYPES.vsReverseMapping(item.plugtype), PLUGIN_NAMES.get(item.guid, 'UNKNOWN'))
            i += 1
        self.report.addEvent('query_plugins', ret)

    def do_I2S_MainC2Command_ALLOCPLUGIN(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_MainC2Command_ADDPLUGINDATA(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_MainC2Command_LOADPLUGIN(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_MainC2Command_HOSTINFO(self, dir, data, cmdHeader):
        hinfo = HostInfoResp()
        #logger.debug('Trying to parse Hostinfo data (offset 0x%x)', len(cmdHeader))
        #hexdump.hexdump(data)
        hinfo.vsParse(data)
        logger.debug('I2S_MainC2Command_HOSTINFO: \n%s', hinfo.tree())
        info = {
            'malware_id' : hinfo.hostid.encode('hex'),
            'malware_version' : hinfo.version,
            'hostname' : hinfo.computername,
            'username' : hinfo.username,
            'malware_note' : hinfo.memo,
            'default_locale' : hinfo.defaultLcid,
            'os_version' : '%d.%d.%d_%d' % (hinfo.osVersionMajor, hinfo.osVersionMinor, hinfo.osVersionBuild, hinfo.osVersionPlatformId),
        }
        self.report.addEvent('profile_host', info)

    def do_I2S_FileComamnd_DRIVE_LIST(self, dir, data, cmdHeader):
        if cmdHeader.status != 0:
            logger.debug('Bad DriveList status')
            return

        i = 0
        off = len(cmdHeader)
        item = DriveListItem()
        ret = []
        while ((i < cmdHeader.extendedStatus) and (off < len(data))):
            off = item.vsParse(data, off)
            info = {
                'drive_letter'  : item.driveName,
                'name'          : item.volumeName,
                'total_space'   : item.totalBytes,
                'free_space'    : item.userFreeBytes,
                'filesystem'    : item.volumeType,
            }
            ret.append(info)
            i += 1
        self.report.addEvent('drive_list', ret)

    def do_I2S_FileComamnd_DIR_LIST(self, dir, data, cmdHeader):
        if cmdHeader.status != 0:
            logger.debug('Bad DirList status')
        cmd = DirListCmd()
        off = cmd.vsParse(data)
        i = 0
        ret = []
        item = c_win32.WIN32_FIND_DATAW()
        while (i < cmdHeader.extendedStatus) and (off < len(data)):
            off = item.vsParse(data, off)
            info = {
                'filename'      : item.cFileName,
                'size'          : ((item.nFileSizeHigh<<32) | item.nFileSizeLow),
                'attributes'    : c_win32.FILE_ATTRIBUTE.vsReverseMapping(item.dwFileAttributes),
                'modified_time' : item.ftLastWriteTime,
                'created_time'  : item.ftCreationTime,
                'accessed_time' : item.ftLastAccessTime,
            }
            ret.append(info)
            i += 1
        self.report.addEvent('dir_list', dict(dir=cmd.directory, result=ret))

    def do_I2S_FileComamnd_FILE_PUT(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_FileComamnd_FILE_PUT_DATA(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_ProxyCommand_CONNECT(self, dir, data, cmdHeader):
        if cmdHeader.status != 0:
            logger.warning('Bad connect status')
            return
        #need to map the msgid <=> connid
        self.proxyConnectResps[cmdHeader.extendedStatus] = cmdHeader.msgId

    def do_I2S_ProxyCommand_DATA(self, dir, data, cmdHeader):

        if cmdHeader.status == ERROR.PROXY_CONN_CLOSED:
            return
        elif cmdHeader.status != 0:
            logger.warning('Bad proxy data: 0x%08x 0x%08x', cmdHeader.status, cmdHeader.extendedStatus)
            hexdump.hexdump(data)
            return
        pdata = data[len(cmdHeader):]
        #logger.debug('Proxy I2S %s', cmdHeader.tree())
        self.addProxyData(dir, cmdHeader.extendedStatus, pdata)

    def addProxyData(self, dir, connid, data):
        conn = self.proxyConns.get(connid)
        if conn is None:
            conn = { 
                IMPLANT_TO_SERVER : cStringIO.StringIO(),
                SERVER_TO_IMPLANT : cStringIO.StringIO(),
            }
            logger.debug('New proxy conn: 0x%08x', connid)
            self.proxyConns[connid] = conn
        conn[dir].write(data)

    def do_I2S_ShellCommand_DEACTIVATE(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_ProxyCommand_DISCONNECT(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_FileComamnd_FILE_GET(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_FileComamnd_FILE_GET_DATA(self, dir, data, cmdHeader):
        resp = FileGetDataResp()
        resp.vsParse(data)
        xfer = self.files.get(resp.guid)
        if xfer is None:
            filename = self.fileGetCmds.get(resp.guid)
            if filename is None:
                raise RuntimeError('Missing FileGet cmd')
            xfer = FileTransferChunk(filename, resp.guid, resp.totalLen)
            self.files[resp.guid] = xfer
        if resp.offset >= resp.totalLen:
            fd = xfer.getFd()
            sha1 = hashlib.sha1()
            sha1.update(fd.read())
            if sha1.digest() != resp.data:
                raise RuntimeError('Sha1 mismatch in file get')
            fd.seek(0)
            if xfer.isComplete():
                md = self.report.addFileFd(fd, xfer.filename)
                self.report.addEvent('file_get', dict(filename=xfer.filename, filemd5=md))
            else:
                raise RuntimeError('File get not complete??')
            fd.close()

        else:
            xfer.addData(resp.data, resp.offset)

    def do_S2I_FileComamnd_FILE_GET(self, dir, data, cmdHeader):
        cmd = FileGetCmd()
        cmd.vsParse(data)
        self.fileGetCmds[cmd.guid] = cmd.filename

    def do_S2I_FileComamnd_FILE_GET_DONE(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_FileComamnd_FILE_GET_DONE(self, dir, data, cmdHeader):
        #not interesting
        pass

    ################################################################################ 
    def do_S2I_MainC2Command_AUTHENTICATE(self, dir, data, cmdHeader):
        cmd = AuthenticateCmd()
        cmd.vsParse(data)
        logger.debug('Server authenticating using password %s', cmd.password)
        self.report.addEvent('c2_authenticate', dict(password=cmd.password))

    def do_S2I_MainC2Command_HOSTINFO(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_S2I_MainC2Command_QUERYPLUGINS(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_S2I_MainC2Command_ALLOCPLUGIN(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_S2I_MainC2Command_ADDPLUGINDATA(self, dir, data, cmdHeader):
        cmd = AddPluginDataCmd()
        cmd.vsParse(data)
        xfer = self.files.get(cmd.guid)
        if xfer is None:
            if PLUGIN_NAMES.get(cmd.guid) is None:
                logger.warning('Missing plugin name:\n%s', cmd.tree())
                hexdump.hexdump(data)
            xfer = FileTransferChunk('plugin_%s.bin' % PLUGIN_NAMES[cmd.guid], cmd.guid, cmd.totalFileLen)
            self.files[cmd.guid] = xfer
            logger.debug('Creating new plugin xfer: %s\n%s', xfer.filename, cmd.tree())
        #logger.warning('Trying to parse addplugin: %s 0x%08x of 0x%08x', PLUGIN_NAMES.get(cmd.guid, None), cmd.offset, cmd.totalFileLen)
        logger.debug('Adding plugin %s: 0x%08x of 0x%08x: 0x%08x bytes', xfer.filename, cmd.offset, cmd.totalFileLen, len(cmd.chunk))
        #pdb.set_trace()
        xfer.addData(cmd.chunk, cmd.offset)

        if xfer.isComplete():
            fd = xfer.getFd()
            md = self.report.addFileFd(fd, xfer.filename)
            info = {
                'filemd5'       : md,
                'module_name'   : xfer.filename,
                'module_id'     : cmd.guid.encode('hex'),
            }
            self.report.addEvent('load_module', info)
            fd.close()
            self.files.pop(cmd.guid, None)
            logger.debug('Adding module: %s %s', md, xfer.filename)


    def do_S2I_MainC2Command_LOADPLUGIN(self, dir, data, cmdHeader):
        #not interesting
        pass
    
    def do_I2S_ShellCommand_ACTIVATE(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_ShellCommand_SHELLOUT(self, dir, data, cmdHeader):
        self.report.addEvent('shell_out', dict(data=data[len(cmdHeader):]))

    def do_I2S_ShellCommand_SHELLIN(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_ScreenCommand_SCREEN_BITMAPINFO(self, dir, data, cmdHeader):
        resp = BitmapInfoResp()
        resp.vsParse(data)
        self.bminfo = resp.data
        self.bmpStruct.vsParse(self.bminfo)

    def do_I2S_ScreenCommand_SCREEN_BITMAPDATA(self, dir, data, cmdHeader):
        resp = BitmapDataResp()
        resp.vsParse(data)
        #logger.warning('do_I2S_ScreenCommand_SCREEN_BITMAPDATA')
        if self.bitmapdata is None:
            self.bitmapdata = FileTransferChunk(None, None, resp.totalLength)
        self.bitmapdata.addData(resp.data, resp.offset)
        if self.bitmapdata.isComplete():
            logger.debug('Saving bitmap: 0x%08x 0x%08x size', self.bitmapdata.currentSize, self.bitmapdata.totalSize)
            fd = self.bitmapdata.getFd()
            bmp = cStringIO.StringIO()
            bmp.write(self.getBitmapFileHeader())
            bmp.write(self.bminfo)
            bmp.write(fd.read())
            bmp.seek(0)
            fd.close()
            md = self.report.addFileFd(bmp, 'screenshot.bmp')
            self.report.addEvent('screenshot', dict(filemd5=md))
            bmp.close()
            self.bitmapdata = None

    def do_S2I_FileComamnd_DRIVE_LIST(self, dir, data, cmdHeader):
        #not interesing -> handled on the I2S side
        pass

    def do_S2I_FileComamnd_DIR_LIST(self, dir, data, cmdHeader):
        #not interesting -> handled completely on the I2S side
        pass

    def do_S2I_ShellCommand_ACTIVATE(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_S2I_ShellCommand_SHELLIN(self, dir, data, cmdHeader):
        sdata = data[len(cmdHeader):]
        idx = sdata.find('\x00')
        if idx >= 0:
            sdata = sdata[:idx]
        self.report.addEvent('shell_in', sdata)

    def do_S2I_ScreenCommand_SCREEN_SCREENSHOT(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_S2I_FileComamnd_FILE_PUT(self, dir, data, cmdHeader):
        cmd = FilePutCmd()
        cmd.vsParse(data)
        xfer = FileTransferChunk(cmd.filename, cmd.guid, cmd.totalLen)
        #duckpunch this in
        xfer.sha1 = cmd.sha1sum
        self.files[cmd.guid] = xfer
        logger.debug('Adding new fileput: %s', cmd.filename)

    def do_S2I_FileComamnd_FILE_PUT_DATA(self, dir, data, cmdHeader):
        cmd = FilePutData()
        cmd.vsParse(data)
        xfer = self.files.get(cmd.guid)
        if xfer is None:
            raise RuntimeError('Missing file put xfer')
        xfer.addData(cmd.data, cmd.offset)
        if xfer.isComplete():
            fd = xfer.getFd()
            sha1 = hashlib.sha1()
            sha1.update(fd.read())
            if sha1.digest() != xfer.sha1:
                raise RuntimeError('Sha1 mismatch in file put')
            fd.seek(0)
            md = self.report.addFileFd(fd, xfer.filename)
            self.report.addEvent('file_put', dict(filename=xfer.filename, filemd5=md))

    def do_S2I_ProxyCommand_CONNECT(self, dir, data, cmdHeader):
        cmd = ProxyConnectCmd()
        cmd.vsParse(data)
        logger.debug('Queueing proxy connect: 0x%08x: %s:%d', cmd.chead.msgId, cmd.hostname, cmd.port)
        self.proxyConnects[cmd.chead.msgId] = (cmd.hostname, cmd.port)

    def do_S2I_ProxyCommand_DATA(self, dir, data, cmdHeader):
        if cmdHeader.status == ERROR.PROXY_CONN_CLOSED:
            pass
        elif cmdHeader.status != 0:
            logger.warning('Bad proxy data: 0x%08x 0x%08x', cmdHeader.status, cmdHeader.extendedStatus)
            hexdump.hexdump(data)
            return
        pdata = data[len(cmdHeader):]
        self.addProxyData(dir, cmdHeader.extendedStatus, pdata)

    def do_S2I_ShellCommand_DEACTIVATE(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_S2I_ProxyCommand_DISCONNECT(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_ProxyCommand_QUERY_CONNECTIONS(self, dir, data, cmdHeader):
        i = 0
        off = len(cmdHeader)
        item = ProxyQueryItem()
        ret = []
        while ((i < cmdHeader.extendedStatus) and (off < len(data))):
            off = item.vsParse(data, off)
            info = {
                'index'         : item.index,
                'run_flag'      : item.runFlag,
                'port'          : item.port,
                'hostname'      : item.hostname,
            }
            ret.append(info)
            i += 1
        self.report.addEvent('query_proxy_connections', ret)

    def do_S2I_ProxyCommand_QUERY_CONNECTIONS(self, dir, data, cmdHeader):
        #logger.warning("Unimplemented: do_S2I_ProxyCommand_QUERY_CONNECTIONS\n %s", hexdump.hexdump(data, result='return'))
        pass

    def do_S2I_MainC2Command_EXIT(self, dir, data, cmdHeader):
        #not interesting
        pass

    def do_I2S_ScreenCommand_SCREEN_SCREENSHOT(self, dir, data, cmdHeader):
        #not interesting
        pass

################################################################################

def handleHttpFlow(report, flow):
    # from inspection there's only 1 request/response, so just pull out the body past the double newline
    resp = flow.fds[SERVER_TO_IMPLANT].read()
    idx = resp.index('\x0d\x0a\x0d\x0a')
    body = resp[idx+4:]
    md1 = report.addFileBytes(body, 'secondstage')
    logger.debug('Add raw secondstage: %s %d bytes', md1, len(body))
    decbody = decodeSecondStage(body)
    md2 = report.addFileBytes(decbody, 'decoded_secondstage')
    logger.debug('Add decoded secondstage: %s %d bytes', md2, len(decbody))

def handleBinaryFlow(report, flow):
    parser = MalarkeyParser(flow, report)
    parser.parse()

g_flowNameRe = re.compile(r"(\d{3}\.\d{3}\.\d{3}\.\d{3})\.(\d{5})-(\d{3}\.\d{3}\.\d{3}\.\d{3})\.(\d{5})")
g_serverPorts = set(['00080', '09443'])

def parseFlow(report, flow):
    logger.debug('Parsing flow %r', flow)
    if flow.tastes[IMPLANT_TO_SERVER].startswith('GET /secondstage'):
        return handleHttpFlow(report, flow)
    elif flow.tastes[IMPLANT_TO_SERVER].startswith('2017'):
        return handleBinaryFlow(report, flow)
    else:
        print('Unknown stream:')
        hexdump.hexdump(flow.tastes[IMPLANT_TO_SERVER])
        #hexdump.hexdump(flow.tastes[SERVER_TO_IMPLANT])

################################################################################

def loadFlowsFromDir(flowDir):
    loadedNames = set()
    ret = []
    for fname in os.listdir(flowDir):
        isClient = False
        if not os.path.isfile(os.path.join(flowDir, fname)):
            #logger.debug('Skipping non-file name: %s', fname)
            continue
        m1 = g_flowNameRe.match(fname)
        if m1 is None:
            #logger.debug('Skipping non-flow name: %s', fname)
            continue
        if fname in loadedNames:
            continue
        #construct expected other side of the flow
        otherSide = '%s.%s-%s.%s' % (m1.group(3), m1.group(4), m1.group(1), m1.group(2))
        if not os.path.isfile(os.path.join(flowDir, otherSide)):
            logger.warning('Otherside of flow is missing: non-file name: %s', otherSide)
            continue
        loadedNames.add(fname)
        loadedNames.add(otherSide)
        isClient = m1.group(4) in g_serverPorts
        if isClient:
            i2sfd = file(os.path.join(flowDir, fname), 'rb')
            s2ifd = file(os.path.join(flowDir, otherSide), 'rb')
            flow = TcpFlow(fname, i2sfd, s2ifd)
            ret.append(flow)
        else:
            s2ifd = file(os.path.join(flowDir, fname), 'rb')
            i2sfd = file(os.path.join(flowDir, otherSide), 'rb')
            flow = TcpFlow(otherSide, i2sfd, s2ifd)
            ret.append(flow)
    return ret
        
################################################################################

def main():
    if (len(sys.argv) != 3) or not os.path.isdir(sys.argv[2]):
        print("Usage: %s <out_dir> <flow_dir>" % sys.argv[0])
        print("  where <out_dir> is the directory to store results to")
        print("  and <flow_dir> is the output directory of running tcpflow on the given pcap")
        return
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    outDir = sys.argv[1]
    flowDir = sys.argv[2]
    print("Processing flows from directory %s" % sys.argv[2])
    flows = loadFlowsFromDir(flowDir)
    print("Loaded %d flows" % len(flows))
    if not os.path.exists(outDir):
        os.mkdir(outDir)
    rep = Report(outDir)
    for flow in flows:
        parseFlow(rep, flow)
    #now output data
    print("Done parsing")
    print('############################################################')
    print('Events:')
    for etype, edata in rep.events:
        if etype == 'shell_out':
            print(etype)
            print(edata['data'])
        else:
            print("%s: %s" % (etype, pprint.pformat(edata)))
    print('############################################################')
    print('Files:')
    for md, name in rep.files:
        print("%s: %s" % (md, name))



if __name__ == '__main__':
    main()
