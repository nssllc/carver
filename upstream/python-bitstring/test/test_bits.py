#!/usr/bin/env python

import unittest
import sys

sys.path.insert(0, '..')
import bitstring
from bitstring.bits import MmapByteArray
from bitstring import Bits, BitArray

class Creation(unittest.TestCase):
    def testCreationFromData(self):
        s = Bits(bytes=b'\xa0\xff')
        self.assertEqual((s.len, s.hex), (16, 'a0ff'))

    def testCreationFromDataWithOffset(self):
        s1 = Bits(bytes=b'\x0b\x1c\x2f', offset=0, length=20)
        s2 = Bits(bytes=b'\xa0\xb1\xC2', offset=4)
        self.assertEqual((s2.len, s2.hex), (20, '0b1c2'))
        self.assertEqual((s1.len, s1.hex), (20, '0b1c2'))
        self.assertTrue(s1 == s2)

    def testCreationFromHex(self):
        s = Bits(hex='0xA0ff')
        self.assertEqual((s.len, s.hex), (16, 'a0ff'))
        s = Bits(hex='0x0x0X')
        self.assertEqual((s.length, s.hex), (0, ''))

    def testCreationFromHexWithWhitespace(self):
        s = Bits(hex='  \n0 X a  4e       \r3  \n')
        self.assertEqual(s.hex, 'a4e3')


    def testCreationFromHexErrors(self):
        self.assertRaises(bitstring.CreationError, Bits, hex='0xx0')
        self.assertRaises(bitstring.CreationError, Bits, hex='0xX0')
        self.assertRaises(bitstring.CreationError, Bits, hex='0Xx0')
        self.assertRaises(bitstring.CreationError, Bits, hex='-2e')

    def testCreationFromBin(self):
        s = Bits(bin='1010000011111111')
        self.assertEqual((s.length, s.hex), (16, 'a0ff'))
        s = Bits(bin='00')[:1]
        self.assertEqual(s.bin, '0')
        s = Bits(bin=' 0000 \n 0001\r ')
        self.assertEqual(s.bin, '00000001')

    def testCreationFromBinWithWhitespace(self):
        s = Bits(bin='  \r\r\n0   B    00   1 1 \t0 ')
        self.assertEqual(s.bin, '00110')

    def testCreationFromOctErrors(self):
        s = Bits('0b00011')
        self.assertRaises(bitstring.InterpretError, s._getoct)
        self.assertRaises(bitstring.CreationError, s._setoct, '8')

    #def testCreationFromIntWithoutLength(self):
    #    s = ConstBitStream(uint=5)
    #    self.assertEqual(s, '0b101')
    #    s = ConstBitStream(uint=0)
    #    self.assertEqual(s, [0])
    #    s = ConstBitStream(int=-1)
    #    self.assertEqual(s, [1])
    #    s = ConstBitStream(int=-2)
    #    self.assertEqual(s, '0b10')


    def testCreationFromUintWithOffset(self):
        self.assertRaises(bitstring.Error, Bits, uint=12, length=8, offset=1)

    def testCreationFromUintErrors(self):
        self.assertRaises(bitstring.CreationError, Bits, uint=-1, length=10)
        self.assertRaises(bitstring.CreationError, Bits, uint=12)
        self.assertRaises(bitstring.CreationError, Bits, uint=4, length=2)
        self.assertRaises(bitstring.CreationError, Bits, uint=0, length=0)
        self.assertRaises(bitstring.CreationError, Bits, uint=12, length=-12)

    def testCreationFromInt(self):
        s = Bits(int=0, length=4)
        self.assertEqual(s.bin, '0000')
        s = Bits(int=1, length=2)
        self.assertEqual(s.bin, '01')
        s = Bits(int=-1, length=11)
        self.assertEqual(s.bin, '11111111111')
        s = Bits(int=12, length=7)
        self.assertEqual(s.int, 12)
        s = Bits(int=-243, length=108)
        self.assertEqual((s.int, s.length), (-243, 108))
        for length in range(6, 10):
            for value in range(-17, 17):
                s = Bits(int=value, length=length)
                self.assertEqual((s.int, s.length), (value, length))
        s = Bits(int=10, length=8)

    def testCreationFromIntErrors(self):
        self.assertRaises(bitstring.CreationError, Bits, int=-1, length=0)
        self.assertRaises(bitstring.CreationError, Bits, int=12)
        self.assertRaises(bitstring.CreationError, Bits, int=4, length=3)
        self.assertRaises(bitstring.CreationError, Bits, int=-5, length=3)

    def testCreationFromSe(self):
        for i in range(-100, 10):
            s = Bits(se=i)
            self.assertEqual(s.se, i)

    def testCreationFromSeWithOffset(self):
        self.assertRaises(bitstring.CreationError, Bits, se=-13, offset=1)

    def testCreationFromSeErrors(self):
        self.assertRaises(bitstring.CreationError, Bits, se=-5, length=33)
        s = Bits(bin='001000')
        self.assertRaises(bitstring.InterpretError, s._getse)

    def testCreationFromUe(self):
        [self.assertEqual(Bits(ue=i).ue, i) for i in range(0, 20)]

    def testCreationFromUeWithOffset(self):
        self.assertRaises(bitstring.CreationError, Bits, ue=104, offset=2)

    def testCreationFromUeErrors(self):
        self.assertRaises(bitstring.CreationError, Bits, ue=-1)
        self.assertRaises(bitstring.CreationError, Bits, ue=1, length=12)
        s = Bits(bin='10')
        self.assertRaises(bitstring.InterpretError, s._getue)

    def testCreationFromBool(self):
        a = Bits('bool=1')
        self.assertEqual(a, 'bool=1')
        b = Bits('bool=0')
        self.assertEqual(b, [0])
        c = bitstring.pack('2*bool', 0, 1)
        self.assertEqual(c, '0b01')

    def testDataStoreType(self):
        a = Bits('0xf')
        self.assertEqual(type(a._datastore), bitstring.bitstore.ConstByteStore)


class Initialisation(unittest.TestCase):
    def testEmptyInit(self):
        a = Bits()
        self.assertEqual(a, '')

    def testNoPos(self):
        a = Bits('0xabcdef')
        try:
            a.pos
        except AttributeError:
            pass
        else:
            assert False

    def testFind(self):
        a = Bits('0xabcd')
        r = a.find('0xbc')
        self.assertEqual(r[0], 4)
        r = a.find('0x23462346246', bytealigned=True)
        self.assertFalse(r)

    def testRfind(self):
        a = Bits('0b11101010010010')
        b = a.rfind('0b010')
        self.assertEqual(b[0], 11)

    def testFindAll(self):
        a = Bits('0b0010011')
        b = list(a.findall([1]))
        self.assertEqual(b, [2, 5, 6])


class Cut(unittest.TestCase):
    def testCut(self):
        s = Bits(30)
        for t in s.cut(3):
            self.assertEqual(t, [0] * 3)


class InterleavedExpGolomb(unittest.TestCase):
    def testCreation(self):
        s1 = Bits(uie=0)
        s2 = Bits(uie=1)
        self.assertEqual(s1, [1])
        self.assertEqual(s2, [0, 0, 1])
        s1 = Bits(sie=0)
        s2 = Bits(sie=-1)
        s3 = Bits(sie=1)
        self.assertEqual(s1, [1])
        self.assertEqual(s2, [0, 0, 1, 1])
        self.assertEqual(s3, [0, 0, 1, 0])

    def testInterpretation(self):
        for x in range(101):
            self.assertEqual(Bits(uie=x).uie, x)
        for x in range(-100, 100):
            self.assertEqual(Bits(sie=x).sie, x)

    def testErrors(self):
        s = Bits([0, 0])
        self.assertRaises(bitstring.InterpretError, s._getsie)
        self.assertRaises(bitstring.InterpretError, s._getuie)
        self.assertRaises(ValueError, Bits, 'uie=-10')


class FileBased(unittest.TestCase):
    def setUp(self):
        self.a = Bits(filename='smalltestfile')
        self.b = Bits(filename='smalltestfile', offset=16)
        self.c = Bits(filename='smalltestfile', offset=20, length=16)
        self.d = Bits(filename='smalltestfile', offset=20, length=4)

    def testCreationWithOffset(self):
        self.assertEqual(self.a, '0x0123456789abcdef')
        self.assertEqual(self.b, '0x456789abcdef')
        self.assertEqual(self.c, '0x5678')

    def testBitOperators(self):
        x = self.b[4:20]
        self.assertEqual(x, '0x5678')
        self.assertEqual((x & self.c).hex, self.c.hex)
        self.assertEqual(self.c ^ self.b[4:20], 16)
        self.assertEqual(self.a[23:36] | self.c[3:], self.c[3:])

    def testAddition(self):
        h = self.d + '0x1'
        x = self.a[20:24] + self.c[-4:] + self.c[8:12]
        self.assertEqual(x, '0x587')
        x = self.b + x
        self.assertEqual(x.hex, '456789abcdef587')
        x = BitArray(x)
        del x[12:24]
        self.assertEqual(x, '0x456abcdef587')
        
class Mmap(unittest.TestCase):
    def setUp(self):
        self.f = open('smalltestfile', 'rb')

    def tearDown(self):
        self.f.close()

    def testByteArrayEquivalence(self):
        a = MmapByteArray(self.f)
        self.assertEqual(a.bytelength, 8)
        self.assertEqual(len(a), 8)
        self.assertEqual(a[0], 0x01)
        self.assertEqual(a[1], 0x23)
        self.assertEqual(a[7], 0xef)
        self.assertEqual(a[0:1], bytearray([1]))
        self.assertEqual(a[:], bytearray([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]))
        self.assertEqual(a[2:4], bytearray([0x45, 0x67]))

    def testWithLength(self):
        a = MmapByteArray(self.f, 3)
        self.assertEqual(a[0], 0x01)
        self.assertEqual(len(a), 3)

    def testWithOffset(self):
        a = MmapByteArray(self.f, None, 5)
        self.assertEqual(len(a), 3)
        self.assertEqual(a[0], 0xab)

    def testWithLengthAndOffset(self):
        a = MmapByteArray(self.f, 3, 3)
        self.assertEqual(len(a), 3)
        self.assertEqual(a[0], 0x67)
        self.assertEqual(a[:], bytearray([0x67, 0x89, 0xab]))
