#!/bin/env python
# Jay Smith (@jay_smif)
# Solver script for Flare-On 5 (2018) Challenge 11
# First run tcpflow on the given pcap to generate a set of TCP-stream files,
# two per TCP stream.
# Then run "python solution.py <pcap_path> <flow_dir>"
#   where <pcap_path> is the path to the input file
#   and <flow_dir> is the directory containing tcpflow output files.


import os
import re
import pdb
import sys
import copy
import hmac
import zlib
import pprint
import struct
import hashlib
import logging
import os.path
import binascii
import cStringIO


try:
    import hexdump
    import scapy.all
    import M2Crypto.EVP
    import M2Crypto.RC4
    import Crypto.Cipher.AES
except ImportError, err:
    print('Failed to import: %s\nPlease install via pip the following:' % str(err))
    print('hexdump')
    print('scapy')
    print('M2Crypto')
    print('pycrypto')
    sys.exit(-1)

try:
    # we used vstruct heavily for declarative structures and parsing, and enums. quite nice
    #https://github.com/vivisect/vivisect
    import vstruct
    from vstruct.primitives import *
    import vstruct.defs.bmp as c_bmp
    import vstruct.defs.win32 as c_win32
except ImportError, err:
    print('Failed to import vstruct. Please make sure that you clone https://github.com/vivisect/vivisect and place that in your PYTHONPATH')
    print('Alternatively you may be able to pip install via:')
    print('   pip install https://github.com/williballenthin/vivisect/zipball/master')
    sys.exit(-1)

logger = logging.getLogger()

def logUnknown(msg, *args, **kwargs):
    hexdata = kwargs.pop('hex', None)
    msg = msg % args
    if hexdata:
        return logger.warning('Unimp: ' + msg + '\n' + hd(hexdata))
    return logger.warning('Unimp: ' + msg)


################################################################################
# stream constants
IMPLANT_TO_SERVER = 0
SERVER_TO_IMPLANT = 1

DirStrings = {
    IMPLANT_TO_SERVER : 'I2S',
    SERVER_TO_IMPLANT : 'S2I',
}


DNS_TYPE_TEXT = 0x10

logger = logging.getLogger()
################################################################################
def hd(bb):
    return hexdump.hexdump(bb, result='return')
################################################################################
def getFdSize(fd):
    pos = fd.tell()
    pos = fd.seek(0, 2)
    size = fd.tell()
    fd.seek(0)
    return size
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
CRYPTO_KEY_SIZE = 0x10
HMAC_KEY_SIZE   = 0x20

CMDSIG  = 0x20180301


PLUGINID = v_enum()
PLUGINID.COMMS_TCP          = 0x50
PLUGINID.COMMS_NAMED_PIPE   = 0x51
PLUGINID.MAINC2             = 0x81
PLUGINID.FILES              = 0x82
PLUGINID.SHELL              = 0x83
PLUGINID.PROXY              = 0x84
PLUGINID.LATERAL            = 0x85
PLUGINID.WGET               = 0x86
PLUGINID.FTP_EXFIL          = 0x87
PLUGINID.ZLIB               = 0x78
PLUGINID.HASHSHA256         = 0x8e
PLUGINID.HMACSHA256         = 0x8f
PLUGINID.AES128_CFB         = 0x92
PLUGINID.CRYPTGENRANDOM     = 0x93


COMMSTYPE_TCP           = 2
COMMSTYPE_PIPE          = 4
COMMSTYPE_CLIENT        = 0
COMMSTYPE_SERVER        = 1

COMMSTYPE = v_enum()
COMMSTYPE.TCPCLIENT     = (COMMSTYPE_TCP  | COMMSTYPE_CLIENT) # 2
COMMSTYPE.TCPSERVER     = (COMMSTYPE_TCP  | COMMSTYPE_SERVER) # 3
COMMSTYPE.PIPECLIENT    = (COMMSTYPE_PIPE | COMMSTYPE_CLIENT) # 4
COMMSTYPE.PIPESERVER    = (COMMSTYPE_PIPE | COMMSTYPE_SERVER) # 5



ERROR = v_enum()
ERROR.SUCCESS                   = 0
#ERROR.BASE                      = 0x100000
#ERROR.BAD_ARGUMENT              = (ERROR.BASE + 1)
#ERROR.API_ERROR                 = (ERROR.BASE + 2)
#ERROR.MISSING_PLUGIN            = (ERROR.BASE + 3)
#ERROR.INTERRUPTED_ALLOC_PLUGIN  = (ERROR.BASE + 4)
#ERROR.MALLOC                    = (ERROR.BASE + 5)
#ERROR.LOAD_PLUGIN               = (ERROR.BASE + 6)
#ERROR.NOT_AUTHENTICATED         = (ERROR.BASE + 7)
#
#ERROR.SHELL_ERROR_BASE               = (ERROR.BASE + 0x1000)
#ERROR.SHELL_NO_COMSPEC               = (ERROR.SHELL_ERROR_BASE + 1)
#ERROR.SHELL_PIPE_ERROR               = (ERROR.SHELL_ERROR_BASE + 2)
#ERROR.SHELL_CREATE_PROC_ERROR        = (ERROR.SHELL_ERROR_BASE + 3)
#ERROR.SHELL_CREATE_THREAD_ERROR      = (ERROR.SHELL_ERROR_BASE + 4)
#ERROR.SHELL_NOT_ACTIVE               = (ERROR.SHELL_ERROR_BASE + 5)
#ERROR.SHELL_WRITE_ERROR              = (ERROR.SHELL_ERROR_BASE + 6)
#ERROR.SHELL_READ_ERROR		     = (ERROR.SHELL_ERROR_BASE + 7)
#ERROR.PROXY_ERROR_BASE		     = (ERROR.BASE + 0x2000)
#ERROR.PROXY_CONN_CLOSED		     = (ERROR.PROXY_ERROR_BASE + 1)
#ERROR.PROXY_ERROR_DISCONNECT	     = (ERROR.PROXY_ERROR_BASE + 2)
#ERROR.FILE_ERROR_BASE		     = (ERROR.BASE + 0x3000)
#ERROR.FILE_EXISTING_FILE_PUT_ERROR   = (ERROR.FILE_ERROR_BASE + 1)
#ERROR.FILE_CREATE_ERROR		     = (ERROR.FILE_ERROR_BASE + 2)
#ERROR.FILE_NOT_OPEN_ERROR	     = (ERROR.FILE_ERROR_BASE + 3)
#ERROR.FILE_GUID_MISMATCH_ERROR	     = (ERROR.FILE_ERROR_BASE + 4)
#ERROR.FILE_ADJUST_FILE_POINTER_ERROR = (ERROR.FILE_ERROR_BASE + 5)
#ERROR.FILE_WRITE_ERROR		     = (ERROR.FILE_ERROR_BASE + 6)
#ERROR.FILE_HASH_INCORRECT_ERROR	     = (ERROR.FILE_ERROR_BASE + 7)
#ERROR.FILE_THREAD_ERROR		     = (ERROR.FILE_ERROR_BASE + 8)
#ERROR.FILE_READ_ERROR		     = (ERROR.FILE_ERROR_BASE + 8)
#ERROR.FILE_NO_SUCH_DIRECTORY_ERROR   = (ERROR.FILE_ERROR_BASE + 9)
#ERROR.SCREEN_ERROR_BASE		     = (ERROR.BASE + 0x4000)
#ERROR.SCREEN_GETDIBITS_ERROR	     = (ERROR.SCREEN_ERROR_BASE + 1)

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
MAINC2CMD.EXIT              = (MAINC2CMD.BASE + 4)
MAINC2CMD.MSGBOX            = (MAINC2CMD.BASE + 5)
MAINC2CMD.DISCONNECT        = (MAINC2CMD.BASE + 6)
MAINC2CMD.AUTHENTICATE      = (MAINC2CMD.BASE + 7)
MAINC2CMD.QUERYPLUGINS      = (MAINC2CMD.BASE + 8)

FILECMD = v_enum()
FILECMD.BASE                = 0
FILECMD.DRIVE_LIST          = (FILECMD.BASE + 1)
FILECMD.DIR_LIST            = (FILECMD.BASE + 2)
FILECMD.CREATE_DIR          = (FILECMD.BASE + 3)
FILECMD.DEL_FILE            = (FILECMD.BASE + 4)
FILECMD.DEL_DIR             = (FILECMD.BASE + 5)
FILECMD.FILE_PUT_DATA       = (FILECMD.BASE + 6)
FILECMD.FILE_PUT_DONE       = (FILECMD.BASE + 7)
FILECMD.FILE_PUT            = (FILECMD.BASE + 8)
FILECMD.FILE_GET_DATA       = (FILECMD.BASE + 9)
FILECMD.FILE_GET_DONE       = (FILECMD.BASE + 10)
FILECMD.FILE_GET            = (FILECMD.BASE + 11)


PROXYCMD = v_enum()
PROXYCMD.CMD_BASE           = 0
PROXYCMD.QUERY_CONNECTIONS  = (PROXYCMD.CMD_BASE + 1)
PROXYCMD.DATA               = (PROXYCMD.CMD_BASE + 2)
PROXYCMD.DISCONNECT         = (PROXYCMD.CMD_BASE + 3)
PROXYCMD.TCPCONNECT         = (PROXYCMD.CMD_BASE + 4)
PROXYCMD.PIPECONNECT        = (PROXYCMD.CMD_BASE + 5)

FTPEXFILCMD = v_enum()
FTPEXFILCMD.CMD_BASE        = 0
FTPEXFILCMD.ACTIVATE        = (FTPEXFILCMD.CMD_BASE + 1)
FTPEXFILCMD.DEACTIVATE      = (FTPEXFILCMD.CMD_BASE + 2)
FTPEXFILCMD.UPLOAD          = (FTPEXFILCMD.CMD_BASE + 3)

LATERALCMD = v_enum()
LATERALCMD.CMD_BASE           = 0
LATERALCMD.ACTIVATE           = (LATERALCMD.CMD_BASE + 1)
LATERALCMD.DEACTIVATE         = (LATERALCMD.CMD_BASE + 2)
LATERALCMD.INSTALL            = (LATERALCMD.CMD_BASE + 3)
LATERALCMD.STOPDELETE         = (LATERALCMD.CMD_BASE + 4)


################################################################################
class RestartException(Exception):
    pass

def getFieldOffset(vstr, seekname):
    for off, indent, name, field in vstr.vsGetPrintInfo():
        if name == seekname:
            return off
    return None
################################################################################


SMB_MAGIC = "\xffSMB"
SMB2_MAGIC = "\xfeSMB"

SMB2_COMMANDS = v_enum()
SMB2_COMMANDS._name                         = 'SMB2_COMMANDS'
SMB2_COMMANDS.READ                          = 8
SMB2_COMMANDS.WRITE                         = 9

class Smb2PacketHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.protocol           = v_bytes(4)
        self.hdrlen             = v_uint16()
        self.credit_charge      = v_uint16()
        self.status             = v_uint32()
        self.command            = v_uint16(enum=SMB2_COMMANDS)
        self.credit             = v_uint16()
        self.flags              = v_uint32()
        self.next_command       = v_uint32()
        self.message_id         = v_uint64()
        self.reserved           = v_uint32()
        self.tree_id            = v_uint32()
        self.session_id         = v_uint64()
        self.signature          = v_bytes(16)
        self.data               = v_bytes(0) # capture maximum

    def vsParse(self, sbytes, offset=0):
        off = vstruct.VStruct.vsParse(self, sbytes, offset)
        if self.next_command == 0:
            # no next command, so take all the rest off
            self.data = v_bytes(vbytes=sbytes[off:])
            off = len(sbytes)
        else:
            # take up to the next command
            datalen = self.next_command - len(self)
            self.data = v_bytes(vbytes=sbytes[off:off+datalen])
            off = offset + self.next_command
        return off


class Smb2WriteReq(vstruct.VStruct):
    def __init__(self, dataoff):
        vstruct.VStruct.__init__(self)
        self.struct_size        = v_uint16()
        self.data_offset        = v_uint16()
        self.data_length        = v_uint32()
        self.offset             = v_uint64()
        self.fid                = GUID()
        self.channel            = v_uint32()
        self.remaining_bytes    = v_uint32()
        self.write_chan_offset  = v_uint16()
        self.write_chan_length  = v_uint16()
        self.flags              = v_uint32()

        self.dataoff = dataoff

    def vsParse(self, sbytes, offset=0):
        vstruct.VStruct.vsParse(self, sbytes, offset)
        dataoff = offset + (self.data_offset - self.dataoff)
        self.data = sbytes[dataoff:dataoff+self.data_length]

class Smb2ReadResp(vstruct.VStruct):
    def __init__(self, dataoff):
        vstruct.VStruct.__init__(self)
        self.struct_size        = v_uint16()
        self.data_offset        = v_uint8()
        self.reserved1          = v_uint8()
        self.data_length        = v_uint32()
        self.read_remaining     = v_uint32()
        self.reserved2          = v_uint32()

        self.dataoff = dataoff

    def vsParse(self, sbytes, offset=0):
        vstruct.VStruct.vsParse(self, sbytes, offset)
        dataoff = offset + (self.data_offset - self.dataoff)
        self.data = sbytes[dataoff:dataoff+self.data_length]

################################################################################


class FtpActivateCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.hostname       = v_wstr(128)
        self.username       = v_wstr(128)
        self.password       = v_wstr(128)
        self.port           = v_uint32()

class FtpUploadCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.localpath      = v_wstr(256)
        self.remotepath     = v_wstr(256)



class MalapropConfig(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.sig            = v_uint32()
        self.commsType      = v_uint32()
        self.port           = v_uint32()
        self.hostname       = v_str(256)
        self.password       = v_wstr(128)
        self.pipename       = v_wstr(128)
        self.memo           = v_wstr(128)
        self.mutex          = v_wstr(128)
        self.servicename     = v_wstr(128)

# size of config + 0x20 byte key
g_EncodedConfigLen = len(MalapropConfig()) + 0x20

class FilePutCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.fileid         = v_uint32()
        self.fileoff        = v_uint64()
        self.filesize       = v_uint64()
        self.filepath       = v_wstr(256)

class FilePutDataCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.fileid         = v_uint32()
        self.fileoff        = v_uint64()
        self.filesize       = v_uint64()
        self.filechunksize  = v_uint64()
        self.bytes          = v_bytes()

    def pcb_filechunksize(self):
        self.vsGetField('bytes').vsSetLength(self.filechunksize)


class TcpConnect(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.port = v_uint32()
        self.hostname = v_str(256)

class PipeConnectCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.hostname = v_wstr(256)
        self.pipename = v_wstr(256)


class LateraralConnectCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.hostname = v_wstr(256)
        self.username = v_wstr(256)
        self.password = v_wstr(256)

class LateraralInstallCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.interactive = v_uint32()
        self.hostname = v_wstr(256)
        self.service = v_wstr(256)
        self.filename = v_wstr(256)
        self.args = v_wstr(256)
        self.encodedConfig = v_bytes(g_EncodedConfigLen)

class MsgEnvelope(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.msgLen         = v_uint32()   # 0x00
        self.hmac           = v_bytes(32)  # 0x04
        self.cryptoType     = v_uint8()    # 0x24
        self.compressType   = v_uint8()    # 0x25
        self.decompressLen  = v_uint32()   # 0x26
        self.iv             = v_bytes(16)  # 0x 

# total size: 48 (0x30)
class HelloChallenge(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.magic00    = v_uint32()   # 0x00
        self.padding04  = v_bytes(4)   # 0x04
        self.magic08    = v_uint32()   # 0x08
        self.padding0c  = v_bytes(4)   # 0x0c
        self.magic10    = v_uint32()   # 0x10
        self.padding14  = v_bytes(28)  # 0x14

class CommandHeader(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.crc32              = v_uint32()
        self.sig                = v_uint32()
        self.plugId             = v_uint32(enum=PLUGINID)
        self.command            = v_uint32()
        self.msgId              = v_uint32()
        self.status             = v_uint32(enum=ERROR)
        self.extendedStatus     = v_uint32()

class DirListCmd(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead              = CommandHeader()
        self.directory          = v_wstr(260)

class DriveListItem(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.totalBytes         = v_uint64()
        self.freeBytes          = v_uint64()
        self.userFreeBytes      = v_uint64()
        self.drivetype          = v_uint32()
        self.volSerialNumber    = v_uint32()
        self.driveName          = v_wstr(4)
        self.volumeName         = v_wstr(128)
        self.volumeType         = v_wstr(128)

PLUGIN_TYPES = v_enum()
PLUGIN_TYPES.Command            = 0x20444d43
PLUGIN_TYPES.Crypto             = 0x54505243
PLUGIN_TYPES.Compression        = 0x504d4f43
PLUGIN_TYPES.HMAC                = 0x43414d48
PLUGIN_TYPES.RAND                = 0x444e4152
PLUGIN_TYPES.HASH                = 0x48534148
PLUGIN_TYPES.NETWORK             = 0x2054454e

class QueryPluginsItem(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.plugId             = v_uint32(enum=PLUGINID)
        self.plugtype           = v_uint32(enum=PLUGIN_TYPES)
        self.name               = v_str(64)
        self.version            = v_str(64)

class HostInfoResp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        self.hostid                 = GUID()
        self.commsType              = v_uint32(enum=COMMSTYPE)
        self.isAdmin                = v_uint32()
        self.defaultLcid            = v_uint32()
        self.osVersionMajor         = v_uint32()
        self.osVersionMinor         = v_uint32()
        self.osVersionBuild         = v_uint32()
        self.osVersionPlatformId    = v_uint32()
        self.computername           = v_wstr(64)
        self.username               = v_wstr(64)
        self.memo                   = v_wstr(256)
        self.version                = v_str(64)

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
        self.type                   = v_uint32(enum=PLUGINID)

class ProxyQueryItemPipe(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.hostname               = v_wstr(256)
        self.pipename               = v_wstr(256)

class ProxyQueryItemTcp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.hostname               = v_str(256)
        self.port                   = v_uint32()
        self.padding                = v_bytes(764)  #union, so need to match proxyqueryitempipe


class FileGetDataResp(vstruct.VStruct):
    def __init__(self):
        vstruct.VStruct.__init__(self)
        self.chead                  = CommandHeader()
        #self.fileId                 = v_uint32()
        self.fileId                 = v_bytes(4)
        self.offset                 = v_uint64()
        self.filesize               = v_uint64()
        self.buffLen                = v_uint64()


################################################################################

ROTATE_BITMASK = {
    8  : 0xff,
    16 : 0xffff,
    32 : 0xffffffff,
    64 : 0xffffffffffffffff,
}


def ror(inVal, numShifts, dataSize=32):
    '''rotate right instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    bitMask = ROTATE_BITMASK[dataSize]
    return bitMask & ((inVal >> numShifts) | (inVal << (dataSize-numShifts)))





g_PluginMap = {
    PLUGINID.SHELL : SHELLCMD,
    PLUGINID.MAINC2 : MAINC2CMD,
    PLUGINID.PROXY : PROXYCMD,
    PLUGINID.FILES : FILECMD,
    PLUGINID.LATERAL : LATERALCMD, 
    PLUGINID.FTP_EXFIL: FTPEXFILCMD,
}

class FileTransfer(object):
    def __init__(self, dir, fileId, filesize, remotePath):
        self.dir = dir
        self.fileId = fileId
        self.filesize = filesize
        self.remotePath = remotePath
        self.blocks = {}
        self.fd = cStringIO.StringIO()

    def addData(self, data, off):
        logger.debug('Adding 0x%08x bytes at 0x%08x', len(data), off)
        self.fd.seek(off)
        self.fd.write(data)

    def isComplete(self):
        return self.fd.tell() >= self.filesize

    def close(self):
        self.fd.close()



class ProxySession(object):
    def __init__(self, connId, hostname = None, port = None):
        self.hostname = hostname
        self.port = port
        self.hasData = False
        self.streams = {
            SERVER_TO_IMPLANT : cStringIO.StringIO(),
            IMPLANT_TO_SERVER : cStringIO.StringIO(),
        }

    def setHost(self, hostname, port=None):
        if self.port is None:
            self.port = port

        if (self.hostname is None) or (len(self.hostname) == 0):
            self.hostname = hostname
        elif self.hostname != hostname:
            logger.debug('Changing hostname from %r to %r', self.hostname, hostname)
            raise RuntimeError('Trying to change hostname for ProxySession')

    def addData(self, dir, data):
        self.hasData = True
        self.streams[dir].write(data)

    def getStream(self, dir):
        return self.streams[dir]

    def close(self):
        for fd in self.streams.values():
            fd.close()



################################################################################

class CustomRc4(object):
    def __init__(self, key, statelen=256, state=None):
        if state is not None:
            self.state = copy.copy(state)
        else:
            self.state = range(statelen)
            j = 0
            for i in range(statelen):
                j = (j + self.state[i] + ord(key[i % len(key)])) % statelen
                self.state[i], self.state[j] = self.state[j], self.state[i]

    def copy(self):
        return CustomRc4(None, state=self.state)

    def gen_random_bytes(self):
        i = 0
        j = 0
        while True:
            i = (i + 1) % len(self.state)
            j = (j + self.state[i]) % len(self.state)
            self.state[i], self.state[j] = self.state[j], self.state[i]
            yield self.state[(self.state[i] + self.state[j]) % len(self.state)]

    def update(self, text):
        cipher_chars = []
        random_byte_gen = self.gen_random_bytes()
        for char in text:
            byte = ord(char)
            cipher_byte = byte ^ random_byte_gen.next()
            cipher_chars.append(chr(cipher_byte))
        return ''.join(cipher_chars)



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
            bytez = fd.read()
            ofile.write(bytez)
        self.files.append( (md, name, bytez) )
        return md

    def addFileBytes(self, bytez, name):
        fd = cStringIO.StringIO()
        fd.write(bytez)
        fd.seek(0)
        ret = self.addFileFd(fd, name)
        fd.close()
        return ret

    def getFileBytes(self, mdseek):
        for md, name, bytez in self.files:
            if mdseek == md:
                return (md, name, bytez)
        return None, None, None

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

class MalapropDnsParser(object):
    def __init__(self, report, packets):
        self.report = report
        self.packets = packets
        self.parts = {}

    def addTxtRecord(self, prefix, rdata):
        #logger.debug('Adding prefix: %s: %s', prefix, hashlib.md5(rdata).hexdigest())
        if prefix in self.parts:
            raise RuntimeError('Unexpected duplicate DNS TXT rec part')
        self.parts[prefix] = rdata

    def finishParse(self):
        fd = self.getAsciiStream()
        encData = self.asciiDecodeStream(fd)
        if len(encData) == 0:
            return
        #logger.debug('Decoded dns data to %d 0x%x bytes\n%s', len(encData),len(encData), hd(encData[:0x200]))
        rc4 = CustomRc4(encData[:0x10], 0xff)
        actualLen = struct.unpack_from('<I', encData, 0x10)[0]
        outData = rc4.update(encData[0x14:])
        #logger.debug('Decrypted data to 0x%x/0x%x bytes: %s\n%s', actualLen, len(outData), hashlib.md5(outData).hexdigest(), hd(outData[:0x200]))
        self.report.addFileBytes(outData, 'malaprop_stage3.dll_')

    def asciiDecodeStream(self, ifd):
        ret = []
        while True:
            ab1 = ifd.read(1)
            if len(ab1) == 0:
                logger.debug('End of Ascii stream encoutnered')
                break
            ab2 = ifd.read(1)
            if len(ab2) != 1:
                raise RuntimeError('Unexpected missing data')
            bb1 = ord(ab1)
            bb2 = ord(ab2)
            bb = ((bb1-0x41)&0x0f) | (((bb2-0x61)&0x0f)<<4)
            ret.append(chr(bb))
        return ''.join(ret)

    def getAsciiStream(self):
        fd = cStringIO.StringIO()
        keys = self.parts.keys()
        keys.sort()
        for key in keys:
            #logger.debug('Adding to stream: %s', key)
            fd.write(self.parts[key])
        fd.seek(0)
        return fd

    def parse(self):
        logger.debug('parseDns: starting on %d packets', len(self.packets))
        for pkt in self.packets:
            if not pkt.haslayer('DNSRR'):
                logUnknown('Unexpected non-DNSRR packet')
                continue
            dnsrr = pkt.getlayer('DNSRR')
            #pdb.set_trace()
            #logger.debug('Handling DNS response to %s', dnsrr.rrname) 
            if dnsrr.rrname[3:] != '.asdflkjsadf.notatallsuspicio.us.':
                raise RuntimeError('Expected bad domain')
            self.addTxtRecord(dnsrr.rrname[:3], dnsrr.rdata)
        self.finishParse()

################################################################################
class MalapropParser(object):
    def __init__(self, flow, report):
        self.flow = flow
        self.report = report
        self.cryptoKey = None
        self.hmacKey = None
        self.proxySessions = {}
        self.currXfer = None
        self.proxyMap = {}

    def parseFtp(self):
        logUnknown('Unimp parseFtp')

    def parseSmb(self):
        srvfd = self.flow.fds[SERVER_TO_IMPLANT]
        clifd = self.flow.fds[IMPLANT_TO_SERVER]
        try:
            logger.debug('Starting smb flow: %r', self.flow)
            newclifd = self.parseSmbStream(clifd, IMPLANT_TO_SERVER)
            newsrvfd = self.parseSmbStream(srvfd, SERVER_TO_IMPLANT)
            logger.debug('Starting custom binary flow over smb: %r', self.flow)
            self.handleKeyExchange(newclifd, newsrvfd)
            self.parseStream(newclifd, SERVER_TO_IMPLANT)
            self.parseStream(newsrvfd, IMPLANT_TO_SERVER)
            self.finishParse()
            newclifd.close()
            newsrvfd.close()
        except Exception, err:
            logger.exception('Error parsing smb: %s', repr(err))

    def parseSmbStream(self, fd, dir):
        # Super-hacky smb parsing. works for a single named pipe connection
        logger.debug('Starting up parseSmbStream %s', DirStrings[dir])
        nbhead = fd.read(4)
        newfd = cStringIO.StringIO()
        while len(nbhead) == 4:
            msglenbuff = '\x00' + nbhead[1:4]
            msglen = struct.unpack_from('>I', msglenbuff)[0]
            if msglen == 0:
                raise RuntimeError('Dropped packets')
            smbmsg = fd.read(msglen)
            if len(smbmsg) != msglen:
                raise RuntimeError('Missing data')
            nbhead = fd.read(4)
            if smbmsg[:4] == SMB_MAGIC:
                # just protocol negotiation
                logger.debug('Skipping SMBv1 message')
                continue
            if smbmsg[:4] != SMB2_MAGIC:
                raise RuntimeError('Unexpected smbv2 magic')
            smb2 = Smb2PacketHeader()
            try:
                smb2.vsParse(smbmsg)
                if (dir == SERVER_TO_IMPLANT) and (smb2.command == SMB2_COMMANDS.READ) and (smb2.status == 0) and (len(smb2.data) != 0):
                    dataoff = getFieldOffset(smb2, 'data')
                    writereq = Smb2WriteReq(dataoff)
                    writereq.vsParse(smb2.data)
                    newfd.write(writereq.data)
                elif (dir == IMPLANT_TO_SERVER) and (smb2.command == SMB2_COMMANDS.WRITE) and (len(smb2.data) != 0):
                    dataoff = getFieldOffset(smb2, 'data')
                    readresp = Smb2ReadResp(dataoff)
                    readresp.vsParse(smb2.data)
                    newfd.write(readresp.data)
            except Exception, err:
                logUnknown('Error during parse: %s', str(err))
        logger.debug('Stopping smb stream')
        newfd.seek(0)
        return newfd
 
    def finishParse(self):
        for connId, proxy in self.proxySessions.items():
            if proxy.hasData:
                self.report.addEvent('proxy_connect', dict(hostname=proxy.hostname, port=proxy.port))
                #flip the directions: s2i is the clifd, i2s is the srvfd
                clifd = proxy.getStream(SERVER_TO_IMPLANT)
                srvfd = proxy.getStream(IMPLANT_TO_SERVER)
                clifd.seek(0)
                srvfd.seek(0)
                clifdsize = getFdSize(clifd)
                srvfdsize = getFdSize(srvfd)
                if (clifdsize == 0) and (srvfdsize == 0):
                    #not sure -> restart issue?
                    continue
                logger.debug('Now handling connId %d: %r %r (%d)(%d)', connId, proxy.hostname, proxy.port, clifdsize, srvfdsize)
                if proxy.hostname is None:
                    logUnknown('Proxy destination unknown. Proceeding with default target host')
                logger.debug('Creating malaprop proxy flow')
                flow = TcpFlow(self.flow.rpr + 'proxy_' + proxy.hostname, clifd, srvfd)
                parseFlow(self.report, flow)
                logger.debug('Just handled inner stream: %r', flow)
            proxy.close()

    def handleKeyExchange(self, fd1, fd2):
        hello1 = HelloChallenge()
        hello2 = HelloChallenge()
        fd1r = fd1.read(len(hello1))
        fd2r = fd2.read(len(hello1))
        if (len(fd1r) != len(hello1)) or (len(fd2r) != len(hello2)):
            raise RuntimeError('Unable to do key exchange')
        hello1.vsParse(fd1r)
        hello2.vsParse(fd2r)
        logger.debug('Using hello1:\n%s', hd(fd1r))
        logger.debug('Using hello2:\n%s', hd(fd2r))
        if (hello2.magic08 != ror(hello2.magic00, 13)) or (hello2.magic10 != (0xffffffff & (~hello2.magic00))):
            raise RuntimeError('Bad hello2')
        if (hello1.magic08 != ror(hello1.magic00, 13)) or (hello1.magic10 != (0xffffffff & (~hello1.magic00))):
            raise RuntimeError('Bad hello1')
  
        tlist = []
        for ii in xrange(len(fd1r)):
            bb = chr(ord(fd1r[ii]) ^ ord(fd2r[ii]) ^ 0xAA)
            tlist.append(bb)
        self.cryptoKey = ''.join(tlist[:CRYPTO_KEY_SIZE])
        self.hmacKey = ''.join(tlist[CRYPTO_KEY_SIZE:])

        logger.debug('Using cryptoKey:\n%s', hd(self.cryptoKey))
        logger.debug('Using hmacKey:\n%s', hd(self.hmacKey))

    def readMsg(self, fd, dir):
        msgLenBuff = fd.read(4)
        if len(msgLenBuff) != 4:
            logger.debug('Ending now')
            return ''
        msgLenVal = struct.unpack_from('<I', msgLenBuff)[0]
        msgLen = msgLenVal & 0xffffff
        hmacId = (msgLenVal>>24) & 0xff
        recvBuff = msgLenBuff + fd.read(msgLen-4)
        if len(recvBuff) != msgLen:
            raise RuntimeError('Did not receive complete msg')
        msgEnv = MsgEnvelope()
        msgEnv.vsParse(recvBuff)
        dataToHash = recvBuff[0x24:]
        #logger.debug('Calculating hmac over data:\n%s', hd(dataToHash))
        mhmac = hmac.new(self.hmacKey, dataToHash, digestmod=hashlib.sha256)
        calcHmac = mhmac.digest()
        #logger.debug('Calculated hmac:\n%s', hd(calcHmac))
        #logger.debug('Received hmac:\n%s', hd(msgEnv.hmac))
        if calcHmac != msgEnv.hmac:
            logUnknown('HMACs differ!')
            return ''
        #logger.debug('HMACs match')
        mungeMsgEnvelope(msgEnv)
        #logger.debug('Demunged header:\n%s', msgEnv.tree())
        if msgEnv.cryptoType != PLUGINID.AES128_CFB:
            raise RuntimeError('Unexpected crypto id')
        if msgEnv.compressType != PLUGINID.ZLIB:
            raise RuntimeError('Unexpected compress id')
        #logger.debug('MsgEnvelope after munging:\n%s', msgEnv.tree())
        evp = M2Crypto.EVP.Cipher(alg='aes_128_cfb', key=self.cryptoKey, iv=msgEnv.iv, op=0, padding=1)
        bytez1 = evp.update(recvBuff[len(msgEnv):])
        #logger.debug('Decrypted data:\n%s', hd(bytez1))

        bytez2 = zlib.decompress(bytez1)
        #logger.debug('Decompressed data:\n%s', hd(bytez2))
        crc = struct.unpack_from('<I', bytez2)[0]
        calccrc = 0xffffffff & binascii.crc32(bytez2[4:])
        if crc != calccrc:
            raise RuntimeError('Incorrect crc!')
        return bytez2

    def getProxySession(self, connId):
        psess = self.proxySessions.get(connId)
        if psess is None:
            psess = ProxySession(connId)
            self.proxySessions[connId] = psess
        return psess

    def parseStream(self, fd, dir):
        try:
            chead = CommandHeader()
            while True:
                msg = self.readMsg(fd, dir)
                if len(msg) == 0:
                    logger.debug('Breaking now')
                    break
                off = chead.vsParse(msg)
                self.dispatch(dir, msg, chead)
        except RestartException:
            raise
        except Exception, err:
            logger.exception('Error handling parseStream %s', str(err))

    def dispatch(self, dir, msg, chead):
        pluginName = PLUGINID.vsReverseMapping(chead.plugId, None)
        if pluginName is None:
            raise RuntimeError('Unknown pluginid')
        cmdName = g_PluginMap[chead.plugId].vsReverseMapping(chead.command, None)
        if cmdName is None:
            raise RuntimeError('Unknown command')
        funcname = 'do_%s_%s_%s' % (DirStrings[dir], pluginName, cmdName) 
        func = getattr(self, funcname, None)
        if func is None:
            logUnknown('No function for: %s', funcname, hex=msg)
        else:
            logger.debug('Dispatching %s', funcname)
            func(dir, msg, chead)

    def parseBinary(self):
        srvfd = self.flow.fds[SERVER_TO_IMPLANT]
        clifd = self.flow.fds[IMPLANT_TO_SERVER]
        try:
            logger.debug('Starting custom binary flow: %r', self.flow)
            self.handleKeyExchange(srvfd, clifd)
            self.parseStream(clifd, IMPLANT_TO_SERVER)
            self.parseStream(srvfd, SERVER_TO_IMPLANT)
            self.finishParse()
        except RestartException, err:
            srvfd.seek(0)
            clifd.seek(0)
            logger.debug('Restarting due to switching direction: %r', self.flow)
            self.handleKeyExchange(srvfd, clifd)
            self.parseStream(srvfd, IMPLANT_TO_SERVER)
            self.parseStream(clifd, SERVER_TO_IMPLANT)
            self.finishParse()
        except Exception, err:
            logger.exception('Error during parse: %s', str(err))


    def do_I2S_FILES_DIR_LIST(self, dir, msg, chead):
        #logUnknown('do_I2S_FILES_DIR_LIST', hex=msg)
        resp = DirListCmd()
        off = resp.vsParse(msg)
        if chead.status == 0:
            ret = []
            item = c_win32.WIN32_FIND_DATAW()
            i = 0
            while (off < len(msg)) and (i < chead.extendedStatus):
                off = item.vsParse(msg, off)
                info = {
                    'filename' : item.cFileName,
                }
                ret.append(info)
                i += 1
            self.report.addEvent('dir_list', dict(dirname=resp.directory, contents=ret))
        else:
            logUnknown('Bad dir list', hex=msg)

    def do_I2S_FILES_DRIVE_LIST(self, dir, msg, chead):
        #logUnknown('do_I2S_FILES_DRIVE_LIST', hex=msg)
        if chead.status == 0:
            item = DriveListItem()
            i = 0
            ret = []
            off = len(chead)
            while (off < len(msg)) and (i < chead.extendedStatus):
                off = item.vsParse(msg, off)
                #print(item.tree())
                i += 1
                info = {
                    'drive_letter' : item.driveName,
                    'name' : item.volumeName,
                    'free_space' : item.freeBytes,
                    'total_space' : item.totalBytes,
                    'filesystem' : item.volumeType,
                    'type' : item.drivetype,
                }
                ret.append(info)
            self.report.addEvent('drive_list', dict(drives=ret))
        else:
            logUnknown('Bad drive list')


    def do_I2S_LATERAL_ACTIVATE(self, dir, msg, chead):
        #logUnknown('do_I2S_LATERAL_ACTIVATE', hex=msg)
        pass

    def do_I2S_LATERAL_DEACTIVATE(self, dir, msg, chead):
        #logUnknown('do_I2S_LATERAL_DEACTIVATE', hex=msg)
        pass

    def do_I2S_LATERAL_INSTALL(self, dir, msg, chead):
        #logUnknown('do_I2S_LATERAL_INSTALL', hex=msg)
        pass

    def do_I2S_MAINC2_AUTHENTICATE(self, dir, msg, chead):
        #logUnknown('do_I2S_MAINC2_AUTHENTICATE', hex=msg)
        if chead.status == 0:
            logger.debug('Authenticated')
        else:
            logUnknown('do_I2S_MAINC2_AUTHENTICATE not authenticated', hex=msg)

    def do_I2S_MAINC2_HOSTINFO(self, dir, msg, chead):
        if len(msg) == 0x1c:
            raise RestartException()
        #logUnknown('do_I2S_MAINC2_HOSTINFO', hex=msg)
        hinfo = HostInfoResp()
        hinfo.vsParse(msg)
        logger.debug('Using hostinfo:\n%s', hinfo.tree())
        info = {
            'hostname' : hinfo.computername,
            'username' : hinfo.username,
            'os_version' : '%d.%d.%d' % (hinfo.osVersionMajor, hinfo.osVersionMinor, hinfo.osVersionBuild),
            'default_locale' :hinfo.defaultLcid,
            'malware_version' : hinfo.version,
            'memo' : hinfo.memo,
            'host_id' : hinfo.hostid,
        }
        self.report.addEvent('host_survey', info)

    def do_I2S_MAINC2_PING(self, dir, msg, chead):
        #logUnknown('do_I2S_MAINC2_PING', hex=msg)
        pass

    def do_I2S_MAINC2_QUERYPLUGINS(self, dir, msg, chead):
        #logUnknown('do_I2S_MAINC2_QUERYPLUGINS', hex=msg)
        item = QueryPluginsItem()
        off = len(chead)
        resp = []
        for i in range(chead.extendedStatus):
            if (off+len(item) > len(msg)):
                print('Warning: breaking early due to missing queryplugins data')
                break
            off = item.vsParse(msg, off)
            #print('%s:%4s:%11s:%s' % (item.guid, item.version, PLUGIN_TYPES.vsReverseMapping(item.plugtype), item.name))
            #print('%08x:%4s:%11s:%s' % (item.plugId, item.version, PLUGIN_TYPES.vsReverseMapping(item.plugtype), PLUGINID.vsReverseMapping(item.plugId)))
            info = {
                'id' : '%08x' % item.plugId,
                'type' : struct.pack('<I', item.plugtype),
                'version' : item.version,
                'name' : item.name,
                'realname' : PLUGINID.vsReverseMapping(item.plugId),
            }
            resp.append(info)
        self.report.addEvent('query_plugins', resp)

    def do_I2S_PROXY_DATA(self, dir, msg, chead):
        #logUnknown('do_I2S_PROXY_DATA', hex=msg)
        psess = self.getProxySession(chead.extendedStatus)
        psess.addData(dir, msg[len(chead):])

    def do_I2S_PROXY_PIPECONNECT(self, dir, msg, chead):
        #logUnknown('do_I2S_PROXY_PIPECONNECT', hex=msg)
        if chead.status == 0:
            logger.debug('do_S2I_PROXY_PIPECONNECT: adding %d -> %d mapping', chead.msgId, chead.extendedStatus)
            self.proxyMap[chead.msgId] = chead.extendedStatus
            psess = self.getProxySession(chead.extendedStatus)
        else:
            logUnknown('Bad PipeConnect resp')

    def do_I2S_PROXY_QUERY_CONNECTIONS(self, dir, msg, chead):
        #logUnknown('do_I2S_PROXY_QUERY_CONNECTIONS', hex=msg)
        if chead.status != 0:
            logUnknown('proxy query connections failed :(')
            return
        off = len(chead)
        connCount = chead.extendedStatus
        item = ProxyQueryItem()
        pipeItem = ProxyQueryItemPipe()
        tcpItem = ProxyQueryItemTcp()
        ret = []
        for i in range(connCount):
            info = {
                    'index' : item.index,
                    'type' : item.type,
            }
            off = item.vsParse(msg, off)
            if item.type == PLUGINID.COMMS_TCP:
                off = tcpItem.vsParse(msg, off)
                info['hostanme'] = tcpItem.hostname
                info['port'] = tcpItem.port
            elif item.type == PLUGINID.COMMS_NAMED_PIPE:
                off = pipeItem.vsParse(msg, off)
                info['hostanme'] = pipeItem.hostname
                info['pipe'] = pipeItem.pipename
            else:
                raise RuntimeError('Unexpected proxy type')
            ret.append(info)
        self.report.addEvent('query_proxy', ret)


    def do_I2S_PROXY_TCPCONNECT(self, dir, msg, chead):
        #logUnknown('do_I2S_PROXY_TCPCONNECT', hex=msg)
        if chead.status == 0:
            logger.debug('do_I2S_PROXY_TCPCONNECT: adding %d -> %d mapping', chead.msgId, chead.extendedStatus)
            self.proxyMap[chead.msgId] = chead.extendedStatus
            psess = self.getProxySession(chead.extendedStatus)
        else:
            logUnknown('Bad TCPConnect resp')

    def do_I2S_SHELL_ACTIVATE(self, dir, msg, chead):
        #logUnknown('do_I2S_SHELL_ACTIVATE', hex=msg)
        pass

    def do_I2S_SHELL_DEACTIVATE(self, dir, msg, chead):
        #logUnknown('do_I2S_SHELL_DEACTIVATE', hex=msg)
        pass

    def do_I2S_SHELL_SHELLIN(self, dir, msg, chead):
        #logUnknown('do_I2S_SHELL_SHELLIN', hex=msg)
        pass

    def do_I2S_SHELL_SHELLOUT(self, dir, msg, chead):
        #logUnknown('do_I2S_SHELL_SHELLOUT', hex=msg)
        self.report.addEvent('shell_out', msg[len(chead):])

    def do_S2I_FILES_DIR_LIST(self, dir, msg, chead):
        #logUnknown('do_S2I_FILES_DIR_LIST', hex=msg)
        pass

    def do_S2I_FILES_DRIVE_LIST(self, dir, msg, chead):
        #logUnknown('do_S2I_FILES_DRIVE_LIST', hex=msg)
        pass

    def do_S2I_LATERAL_ACTIVATE(self, dir, msg, chead):
        #logUnknown('do_S2I_LATERAL_ACTIVATE', hex=msg)
        latcmd = LateraralConnectCmd()
        latcmd.vsParse(msg, len(chead))
        info = {
            'hostname' : latcmd.hostname,
            'username' : latcmd.username,
            'password' : latcmd.password,
        }
        self.report.addEvent('lateral_activate', info)

    def do_S2I_LATERAL_DEACTIVATE(self, dir, msg, chead):
        #logUnknown('do_S2I_LATERAL_DEACTIVATE', hex=msg)
        self.report.addEvent('lateral_deactiveate', None)

    def do_S2I_LATERAL_INSTALL(self, dir, msg, chead):
        #logUnknown('do_S2I_LATERAL_INSTALL', hex=msg)
        lcmd = LateraralInstallCmd()
        lcmd.vsParse(msg, len(chead))
        info = {
                'hostname' : lcmd.hostname,
                'service' : lcmd.service,
                'filename' : lcmd.filename,
                'args' : lcmd.args,
                }
        self.report.addEvent('lateral_install', info)
        decConfig = decodeConfig(lcmd.encodedConfig[0x20:], lcmd.encodedConfig[:0x20])
        malconf = MalapropConfig()
        malconf.vsParse(decConfig)
        #pdb.set_trace()
        info = {
            'commstype' : malconf.commsType,
            'port' : malconf.port,
            'hostname' : malconf.hostname,
            'password' : malconf.password,
            'pipename' : malconf.pipename,
            'memo': malconf.memo,
            'mutex' : malconf.mutex,
            'servicename' :malconf.servicename,
        }
        self.report.addEvent('lateral_config', info)

    def do_S2I_MAINC2_AUTHENTICATE(self, dir, msg, chead):
        #logUnknown('do_S2I_MAINC2_AUTHENTICATE', hex=msg)
        password = v_zwstr()
        password.vsParse(msg, len(chead))
        self.report.addEvent('authenticate', dict(password=str(password)))

    def do_S2I_MAINC2_EXIT(self, dir, msg, chead):
        #logUnknown('do_S2I_MAINC2_EXIT', hex=msg)
        self.report.addEvent('exit', None)

    def do_S2I_MAINC2_HOSTINFO(self, dir, msg, chead):
        #logUnknown('do_S2I_MAINC2_HOSTINFO', hex=msg)
        pass

    def do_S2I_MAINC2_PING(self, dir, msg, chead):
        #logUnknown('do_S2I_MAINC2_PING', hex=msg)
        pass

    def do_S2I_MAINC2_QUERYPLUGINS(self, dir, msg, chead):
        #logUnknown('do_S2I_MAINC2_QUERYPLUGINS', hex=msg)
        pass

    def do_S2I_PROXY_DATA(self, dir, msg, chead):
        #logUnknown('do_S2I_PROXY_DATA', hex=msg)
        psess = self.getProxySession(chead.extendedStatus)
        psess.addData(dir, msg[len(chead):])

    def do_S2I_PROXY_PIPECONNECT(self, dir, msg, chead):
        #logUnknown('do_S2I_PROXY_PIPECONNECT', hex=msg)
        tcpconn = PipeConnectCmd()
        tcpconn.vsParse(msg, len(chead))
        connId = self.proxyMap.get(chead.msgId)
        if connId is None:
            raise RuntimeError('Bad msgid->connid map')
        psess = self.getProxySession(connId)
        psess.setHost(tcpconn.hostname, 445)

    def do_S2I_PROXY_QUERY_CONNECTIONS(self, dir, msg, chead):
        #logUnknown('do_S2I_PROXY_QUERY_CONNECTIONS', hex=msg)
        pass

    def do_S2I_PROXY_TCPCONNECT(self, dir, msg, chead):
        #logUnknown('do_S2I_PROXY_TCPCONNECT', hex=msg)
        tcpconn = TcpConnect()
        tcpconn.vsParse(msg, len(chead))
        connId = self.proxyMap.get(chead.msgId)
        if connId is None:
            raise RuntimeError('Bad msgid->connid map')
        psess = self.getProxySession(connId)
        psess.setHost(tcpconn.hostname, tcpconn.port)

    def do_S2I_SHELL_ACTIVATE(self, dir, msg, chead):
        #logUnknown('do_S2I_SHELL_ACTIVATE', hex=msg)
        pass

    def do_S2I_SHELL_DEACTIVATE(self, dir, msg, chead):
        #logUnknown('do_S2I_SHELL_DEACTIVATE', hex=msg)
        self.report.addEvent('shell_deactiveate', None)

    def do_S2I_SHELL_SHELLIN(self, dir, msg, chead):
        #logUnknown('do_S2I_SHELL_SHELLIN', hex=msg)
        shelldata = msg[len(chead):].replace('\x00', '').strip()
        self.report.addEvent('shell_in', shelldata)

    def do_I2S_FILES_FILE_PUT(self, dir, msg, chead):
        #logUnknown('do_I2S_FILES_FILE_PUT', hex=msg)
        pass

    def do_I2S_FILES_FILE_PUT_DATA(self, dir, msg, chead):
        #logUnknown('do_I2S_FILES_FILE_PUT_DATA', hex=msg)
        pass

    def do_I2S_FILES_FILE_PUT_DONE(self, dir, msg, chead):
        #logUnknown('do_I2S_FILES_FILE_PUT_DONE', hex=msg)
        pass

    def do_S2I_FILES_FILE_PUT(self, dir, msg, chead):
        #logUnknown('do_S2I_FILES_FILE_PUT', hex=msg)
        fput = FilePutCmd()
        fput.vsParse(msg, len(chead))
        if self.currXfer is not None:
            raise RuntimeError('Unexpected dual file xfer')
        self.currXfer = FileTransfer(SERVER_TO_IMPLANT, fput.fileid, fput.filesize, fput.filepath)
        logger.debug('Creating file put: %s', fput.filepath)

    def do_S2I_FILES_FILE_PUT_DATA(self, dir, msg, chead):
        #logUnknown('do_S2I_FILES_FILE_PUT_DATA', hex=msg)
        fpdata = FilePutDataCmd()
        fpdata.vsParse(msg, len(chead))
        if self.currXfer is None:
            raise RuntimeError('Unexpected missing xfer')
        self.currXfer.addData(fpdata.bytes, fpdata.fileoff)
        if self.currXfer.isComplete():
            self.currXfer.fd.seek(0)
            md = self.report.addFileFd(self.currXfer.fd, self.currXfer.remotePath)
            self.report.addEvent('file_put', dict(filepath=self.currXfer.remotePath, md5sum=md))
            self.currXfer.close()
            self.currXfer = None
        else:
            logger.debug('CurrXfer not yet complete: 0x%x of 0x%x', self.currXfer.fd.tell(), self.currXfer.filesize)

    def do_S2I_FILES_FILE_PUT_DONE(self, dir, msg, chead):
        #logUnknown('do_S2I_FILES_FILE_PUT_DONE', hex=msg)
        if self.currXfer is not None:
            #raise RuntimeError('Unexpected missing xfer')
            self.currXfer.fd.seek(0)
            md = self.report.addFileFd(self.currXfer.fd, self.currXfer.remotePath)
            self.report.addEvent('file_put', dict(filepath=self.currXfer.remotePath, md5sum=md))
            self.currXfer.close()
            self.currXfer = None

    def do_S2I_FTP_EXFIL_ACTIVATE(self, dir, msg, chead):
        #logUnknown('do_S2I_FTP_EXFIL_ACTIVATE', hex=msg)
        fcmd = FtpActivateCmd()
        fcmd.vsParse(msg, len(chead))
        info = {
                'hostname' :fcmd.hostname,
                'username' :fcmd.username,
                'password' :fcmd.password,
                'port' :fcmd.port,
        }
        self.report.addEvent('ftp_activate', info)

    def do_S2I_FTP_EXFIL_DEACTIVATE(self, dir, msg, chead):
        #logUnknown('do_S2I_FTP_EXFIL_DEACTIVATE', hex=msg)
        pass

    def do_S2I_FTP_EXFIL_UPLOAD(self, dir, msg, chead):
        #logUnknown('do_S2I_FTP_EXFIL_UPLOAD', hex=msg)
        fcmd = FtpUploadCmd()
        fcmd.vsParse(msg, len(chead))
        info = {
                'localpath' :fcmd.localpath,
                'remotepath' :fcmd.remotepath,
        }
        self.report.addEvent('ftp_upload', info)

################################################################################
 

g_flowNameRe = re.compile(r"(\d{3}\.\d{3}\.\d{3}\.\d{3})\.(\d{5})-(\d{3}\.\d{3}\.\d{3}\.\d{3})\.(\d{5})")
g_serverPorts = set(['00080', '09443', '00445'])


################################################################################
def isMalapropTaste(taste):
    if len(taste) < 0x20:
        return False
    hello = HelloChallenge()
    hello.vsParse(taste)
    if (hello.magic08 == ror(hello.magic00, 13)) and (hello.magic10 == (0xffffffff & (~hello.magic00))):
        return True
    return False


################################################################################
def decodeConfig(clearConfig, xorArray):
    ret = []
    for ii, bb in enumerate(clearConfig):
        cc = ret.append( chr( (0xff & ((ord(bb) ^ ord(xorArray[ii % len(xorArray)])) + ii)) ) )
    return ''.join(ret)

################################################################################
def parseDns(report, packets):
    parser = MalapropDnsParser(report, packets)
    parser.parse()

################################################################################
def generateHttpReqs(fd):
    # first the headers
    while True:
        req = {}
        line = fd.readline()
        if len(line) == 0:
            return 
        #logUnknown('HTTP path line:', hex=line)
        if line.startswith('GET'):
            #http request
            req['urlpath'] = line.split()[1]
        elif line.startswith('HTTP/1') and ('200' in line):
            #http response
            _, rcode, msg = line.split(' ', 2)
            req['rcode'] = int(rcode)
            req['status'] = msg
        else:
            raise RuntimeError('Only GET or 200-OK supported')
        # now read all the headers
        while True:
            line = fd.readline().strip()
            #logUnknown('Handle http header', hex=line)
            if len(line) == 0:
                break
            hname, hval = line.split(':', 1)
            hname = hname.lower()
            req[hname] = hval
        # now read the body (if any)
        clen = req.get('content-length')
        if clen is None:
            req['body'] = ''
        else:
            req['body'] = fd.read(int(clen))
        #logger.debug('Yielding req:\n%s', pprint.pformat(req))
        yield req

def parseSimpleHttp(report, flow):
    logger.debug('Doing I2S http generate')
    reqs = [req for req in generateHttpReqs(flow.fds[IMPLANT_TO_SERVER])]
    logger.debug('Doing S2I http generate')
    resps = [resp for resp in generateHttpReqs(flow.fds[SERVER_TO_IMPLANT])]
    if len(reqs) != len(resps):
        raise RuntimeError('Unmatched http reqs/resps')
    for req, resp in zip(reqs, resps):
        md = report.addFileBytes(resp['body'], req['urlpath'])
        logger.debug('Added HTTP body: %s %s', md, req['urlpath'])
    

################################################################################

def parseFlow(report, flow):
    logger.debug('Parsing flow %r', flow)
    #if flow.tastes[IMPLANT_TO_SERVER].startswith('GET /secondstage'):
    #    return handleHttpFlow(report, flow)
    #elif flow.tastes[IMPLANT_TO_SERVER].startswith('2017'):
    #    return handleBinaryFlow(report, flow)
    #else:
    if 'wiki.flare.fireeye.com' in repr(flow):
        parseSimpleHttp(report, flow)
        return
    if '00021' in repr(flow) and (flow.tastes[IMPLANT_TO_SERVER].startswith('USER')):
        logger.debug('Ignoring FTP control channel')
        #logUnknown('Handle ftp control: I2S\n%s', flow.tastes[IMPLANT_TO_SERVER])
        #logUnknown('Handle ftp control: S2I\n%s', flow.tastes[SERVER_TO_IMPLANT])
        return
    if '49162' in repr(flow) and ('SMB' in flow.tastes[IMPLANT_TO_SERVER][0:0x10]):
        parser = MalapropParser(flow, report)
        parser.parseSmb()
        return 
    if '00445' in repr(flow) and ('SMB' in flow.tastes[IMPLANT_TO_SERVER][0:0x10]):
        logger.info('Skipping SMB flow with lateral spreading')
        return
    if '09443' in repr(flow):
        parser = MalapropParser(flow, report)
        parser.parseBinary()
        return
    if '00443' in repr(flow) and ('github.com' in flow.tastes[IMPLANT_TO_SERVER][:0x200]):
        logger.debug('Skipping github TLS traffic')
        return
    if '54733' in repr(flow) and flow.tastes[IMPLANT_TO_SERVER].startswith('cryptar'):
        #ftp data channel. just store the data
        report.addFileFd(flow.fds[IMPLANT_TO_SERVER], 'level9.crypt')
        return
    logUnknown('Unknown stream: %r\n%s', flow, hd(flow.tastes[IMPLANT_TO_SERVER]))

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
            logUnknown('Assuming empty side of flow due to missing file: %s', otherSide)
            # touch it to stop getting these errors
            with file(os.path.join(flowDir, otherSide), 'wb') as ofile:
                logger.info('Created empty file: %s', otherSide)
                pass
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
def mungeMsgEnvelope(msgEnv):
    #does the crappy xor of the header values
    msgEnv.cryptoType = msgEnv.cryptoType ^ ord(msgEnv.iv[0])
    msgEnv.compressType = msgEnv.compressType ^ ord(msgEnv.iv[1])
    msgEnv.decompressLen = msgEnv.decompressLen ^ struct.unpack_from('<I', msgEnv.iv, 2)[0]

################################################################################
def loadDnsTextResponsesFromPcap(pcapPath):
    '''
    Returns a list of scapy packets containing DNSRR layers for TEXT types
    '''
    packets = scapy.all.rdpcap(pcapPath)
    ret = []
    for pk in packets:
        if not pk.haslayer('DNSRR'):
            continue
        if pk.getlayer('DNSRR').type != DNS_TYPE_TEXT:
            continue
        ret.append(pk)
    return ret

################################################################################

def printUsage(argv):
    print('python %s [pcap_path] [flow_path]' % argv[0])
    print('Process the pcap at [pcap_path] and the flows at [flow_path]')
    print('If these are not provided, assumes that [pcap_path] is ./pcap.pcap')
    print('and [flow_path] is ./flows')

def getInputPaths():
    pcapPath = 'pcap.pcap'
    flowPath = 'flows'
    if (len(sys.argv) > 3):
        printUsage(sys.argv)
        sys.exit(-1)
    if len(sys.argv) > 1:
        if os.path.exists(sys.argv[1]):
            pcapPath = sys.argv[1]
        else:
            print('Bad pcap path')
            printUsage(sys.argv)
            sys.exit(-1)
    if len(sys.argv) > 2:
        if os.path.exists(sys.argv[2]):
            flowPath = sys.argv[2]
        else:
            print('Bad flow path')
            printUsage(sys.argv)
            sys.exit(-1)
    return 'dumpdir', pcapPath, flowPath

def postProcess(report):
    # now process the captured
    md, name, bytez = report.getFileBytes('81ce35acb25c57257e0517ff0f379e8c')
    if bytez is None:
        logUnknown('Failed to post-process level9.crypt')
        return
    fd = cStringIO.StringIO(bytez)
    decodeCryptarFile(report, fd)
    fd.close()

g_fileId = 'cryptar'
g_KeyData = {
 "20180620" : 'UpIvmFvBUO/TfX3zoxcUkaldhBcxQMw0kpt+TYnwbWE=',
 "20180621" : '2ffrzaquK+qmjepgNHu4EDnEjWGoxHetzwWn5fpV95c=',
 "20180622" : "DKT8egTsPvSYoTvX+YGASr5yIyF9FuvZGywM0Agqc4k=",
 "20180623" : "PAY3qjDtPfGDO88HhDSbl/PeeldDZ2nru1WoXHizKCY=",
 "20180624" : "2ENxx3/8Pv+D4MyKwtJq8hEfOJjJtDCvVRvzT+V/Re0=",
 "20180625" : "ubGLVkgjy1Z1V7O+Pw/RisF0ORQEtOXk9LvNQ/qLykI=",
 "20180626" : "zJNUHUMYXgz8MxJ4QOuiC2A4EzAsq2JSXhe6t8JKmrA=",
 "20180627" : "0uShUJvJ05kzT6ZEDaA4ZL+f56W0Z+60V1OCiKqb+UU=",
 "20180628" : "gLp9tetjUsS/+GhmQZUOAFs2pL4Z9XiGDrgGQS/OoCY=",
 "20180629" : "j1ybV7tCWNCOk5j9cble3wJmkpYJcyCrIyGlge3NJF0=",
 "20180630" : "7EWkzKFD0mPrT0h0CPh6pVlEIGPO9xE2KqpRmLpNyHk=",
 "20180701" : "UzLB6+CXfnUN2vZ7VMWlvFl1ic6fA1k2y5P5xVU+hjs=",
 "20180702" : "a9ylQu0YDOP2ZQXgaaX61ER2gFsi89hrLQtxsEVT/sY=",
 "20180703" : "AfMAC+wK5yeZwfM6r+3pIi5/9/RucZC8OHxqNzFJFE4=",
 "20180704" : "P3TxMLTJ125QTclJjI4SSwzwTq5uVKB3Qla+dgxNvw0=",
 "20180705" : "b4Z9ESNOuV3iVvnPDpGXhY0BxUm2FCLO/OEgsDsAJ2A=",
 "20180706" : "ODSZG3zKCxGBbyGF08LcgfLPKy2EW5ltBtXY4i+FbFA=",
 "20180707" : "55xG79FawZZySbuQapc7oVwdZo3A3aqmFmTmsffkYRI=",
 "20180708" : "8IognEg//IUf3eijw2EKELYyMt0e/qk/hnAZZaP6s+8=",
 "20180709" : "9WLpWLD9jd6cPUGZjqg6mhZPKWVOHL4+JSG/LN7uQU0=",
 "20180710" : "6y2uJpyGLusOE4KyLLU9pe9lPWnTRdviURxFRi+wsP4=",
 "20180711" : "JG5fEdVoqYZTTGt5lG35w+mtCX2vkFw3T707PrdR/80=",
 "20180712" : "/F0izUakg4DSmJNpqFIExmgd4WTfC6d2sWxUxexH4QQ=",
 "20180713" : "C4jSOcsslM5aX5aS61I2pecg4ogxA9DxktY8qjwVUyk=",
 "20180714" : "L6gRiWQZhTDiipZYHrXjDYr+3GQO0KnTum7DMdBMcVA=",
 "20180715" : "25CDpP6o73PWKdjDnWmQaypfH0UDHCNaaW8BzhdAIYI=",
 "20180716" : "gj9CJC9oCYoYfNtc8HW1KtPMXvf9VPqMBFUS/qG0Lh4=",
 "20180717" : "2DdyZE9tnvLqd3HZqSCKvjLe40H03OQt+OxxZ+6Sr6w=",
 "20180718" : "XSTxORuqjZLcrEkA7k/uYo7xRU3fqrsy0T54ItKvdnE=",
 "20180719" : "wm6gjVIzV0BrBdpMyCwrizlOYFjQBg638gr7UVgIE5Q=",
 "20180720" : "oXB4QI9v86d77H2MKlxv8pVy8kna+il06fLiOvkpDjs=",
 "20180721" : "tA9WuqydPg5rEw6bYA8T19bB5iBpsTGP16JgwtHxeNA=",
 "20180722" : "DAuYxIYEMt6mDx/CGSPIp0okf/95KKVQWxiRogg295E=",
 "20180723" : "YrUxgis2iBlRsFUSFHhWbZHgITN1D9N70arBt6wEiSE=",
 "20180724" : "vVhN+Xangc4K+zJgkD1drBnWz8TA5a2B5ozP1sfh77s=",
 "20180725" : "cHtwHsS4sI5r6y05j1W+vKPFEVuGcgdTd1TAy+ssR4g=",
 "20180726" : "uiFtHOKOUho/Z643yEpGRRmgZ9BqfgPor3hviSFo8m8=",
 "20180727" : "VnoGdNrCHls/q2D7yZ1hWMUH+/EprIxv+uuFTAdeAys=",
 "20180728" : "guqonylNB4SiNEWXSd39sZO7RcexPArGSJtI0hQQjdw=",
 "20180729" : "0QXIF/aKuMkoEpgFmYcZss0bxIN3zpzCGuWto+q+edw=",
 "20180730" : "YH6VNUykJ0UzQSPlmC2V5/oBN40ku+3tFaoIByZS+ls=",
 "20180731" : "s0T6cMfagWwshMPCuujREhhFFJXevsn3fDpRHUypLRM=",
 "20180801" : "AFDC1Evq0+9WyAJE7C++fPOv09ELKSNynf+DGJAgfYY=",
 "20180802" : "9pJ6I0pqoi3NRZepkKrWE2iQghsYjI+0IpdlOZVxO9I=",
 "20180803" : "dZxm/xJd2rbWhs51J8La70+0Ry+5BvtOC1BthZ4o9Fs=",
 "20180804" : "27wgWiPQ5ArJG+atqHYe5OgM9bxqjal5FGSb90yitz0=",
 "20180805" : "T0UKU8d/yWfrMO9FdBbv8Uh4+GUl2biVuaTDj6zF+/k=",
 "20180806" : "/wSJM2ruefYRFuIDpdBGDocQii7htFSh9wNUkgB+pMI=",
 "20180807" : "odbz8AGA/1W56ath1WQRWUZ408NxmHNYVaCJe6fZLsc=",
 "20180808" : "0ia/UPCsI01mFyTTbSVvOmno5NqjBgmEtVNGUV/uTVk=",
 "20180809" : "YfX7ygEifLPd185HRo+Dp2O6e6Ode0D7KVJLblTygaY=",
 "20180810" : "YFaxYE39D6Ko6MDe6VuyIB006rlsxqgVEQW81PwRMQo=",
 "20180811" : "OMgvGqUK13X7LXjWnnh2FXdD0J2bKA/A+UaskCDMqao=",
 "20180812" : "9RoyOCS0Ei0LzBw98n4A4YcaGkxWiW97zP+XvYfnTx8=",
 "20180813" : "V05nC/ILP6kIf9ctNqoEWetJeeB9OcBjROpmwKUdS3Y=",
 "20180814" : "3kE8+862EmeRFzIofOcaKm01lXlw2io8gyz8RhAlC4k=",
 "20180815" : "4sbd/8TuqsgOP4Mehuoed6jOkXttPh0RXuRCqwMOXMw=",
 "20180816" : "CkQGarc+Mve/bOT03DfpwNfY4fwlTo1YruvX4EkgECU=",
 "20180817" : "j9KuzswQeHA93BpXTRKNNjU2hua1xJkOuacAlc2UaNc=",
 "20180818" : "xx3hTbMw4Xl4QVgKacCsKvXwgfOG8NHtX9bG8p4Zk+Y=",
 "20180819" : "aivNYPGTOzIZWPRp8xnnjDrUa0AOQTiBGHmOpCeoMFg=",
 "20180820" : "kIe3obq7Ki5N6QPJyQj/YrQxK4CI5AUwUigpDcQR6hw=",
 "20180821" : "nvaTJE2E58nU6fl8OGm9E61oBg5gFjZEo+CLBc49SFA=",
 "20180822" : "mnahdz0c5dR/IRbbrzTY5Q/VSzvWJhlpaDHr2XGaOUI=",
 "20180823" : "ZsC4G8T4AvGnXCwJRMNVa4FfHhmBMOfkIZBg0w2352g=",
 "20180824" : "CD6545mUCJAjppHxeV/vrHG8FndIeq2I40NeiWdJoUo=",
 "20180825" : "WjghDDhD7ZGIBLhP4T1PwuLBE6anx3LHLk15Fz9XS+A=",
 "20180826" : "ugXMLlqLSJH3QegcNJ+J2Nqw5xeqwA0j17PjfX/UM9k=",
 "20180827" : "hXJTgQOcQJA+E81GzykpdMEpH5Q4x6t6owRvX+74DJY=",
 "20180828" : "hh2nfEdY0eE8aGk0G9KG/57T0KIVERtWtu7WacWz2yk=",
 "20180829" : "aapFxQk22dgELgvSfIo6xZblFFIbtHMQIZJE+A23cMg=",
 "20180830" : "2KVPxIMx5m+Q6dlJi0hyQoLkBTHpq5n9Osye0uIspIM=",
 "20180831" : "BcUZckt2F9xOQCB+Trd5jeVi9gxwbeGMDr4NjRFYkB8=",
}



def getKeyMaterial(istr):
    rbytes = istr.decode('base64')
    return(rbytes[:16], rbytes[16:])

def _unpad(s):
    return s[:-ord(s[len(s)-1:])]

def decryptFile(fd, key, iv):
    idata = fd.read()
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    decData = _unpad(cipher.decrypt(idata))
    return decData

def processCryptarSubFile(report, ibytes, off):
    logger.debug('Processing file at 0x%08x' % off)
    pathLen = struct.unpack_from('<I', ibytes, off)[0]
    off += 4
    filepath = ibytes[off:off+pathLen].decode('utf8')
    off += pathLen
    filehash = ibytes[off:off+32]
    off += 32
    fileLen = struct.unpack_from('<Q', ibytes, off)[0]
    off += 8
    logger.debug('Looking at file bytes starting at offset 0x%08x - 0x%08x', off, off+fileLen)
    fileBytes = ibytes[off:off+fileLen]
    off += fileLen
    shaobj = hashlib.sha256(fileBytes)
    md5obj = hashlib.md5(fileBytes)
    if shaobj.digest() == filehash:
        logger.debug('Hashes match!')
    else:
        logger.warning('Hashes differ')
    report.addFileBytes(fileBytes, filepath)
    logger.info('Processed file (%x)%s: (%x)%s', pathLen, filepath, fileLen, md5obj.hexdigest())
    return off

def decodeCryptarFile(report, fd):
    magic = fd.read(len(g_fileId))
    if magic != g_fileId:
        logUnknown('Unexpected magic bytes')
        return
    cid = fd.read(8)
    cryptData = g_KeyData.get(cid)
    if cryptData is None:
        raise RuntimeError('Unexpected test cryptid')
    key, iv = getKeyMaterial(cryptData)
    logger.debug('Using key material from %s: 0x%x bytes',  cid, len(key))
    decContents = decryptFile(fd, key, iv)
    off = 0
    while off < len(decContents):
        off = processCryptarSubFile(report, decContents, off)
        logger.debug('New off: %08x of %08x' %(off, len(decContents)))
    logger.debug('Done with cryptar file')

def main():
    logging.basicConfig(level=logging.DEBUG)
    logger.info('Starting up')
    outDir, pcapPath, flowPath = getInputPaths()    
    logger.info('Using paths: %s %s', pcapPath, flowPath)
    if not os.path.exists(outDir):
        os.mkdir(outDir)
    rep = Report(outDir)

    dnsPackets = loadDnsTextResponsesFromPcap(pcapPath)
    print('Loaded %d DNS responses' % len(dnsPackets))
    logger.info('Processing DNS now')
    parseDns(rep, dnsPackets)

    flows = loadFlowsFromDir(flowPath)
    print("Loaded %d flows" % len(flows))

    for flow in flows:
        parseFlow(rep, flow)
    postProcess(rep)
    #now output data
    print("Done parsing")
    print('############################################################')
    print('Events:')
    for etype, edata in rep.events:
        if etype == 'shell_out':
            print(etype)
            print(edata)
        else:
            print("%s: %s" % (etype, pprint.pformat(edata)))
    print('############################################################')
    print('Files:')
    for md, name, bytez in rep.files:
        print("%s: %s" % (md, name))




if __name__ == '__main__':
    main()
