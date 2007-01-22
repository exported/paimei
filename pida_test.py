import unittest
import os

from pida import *
from pgraph import *

class TestFunctionClass(unittest.TestCase):
    def setUp(self):
        filepath = os.getcwd() + "\\testdb"
        filepath = filepath.replace("\\", "/")
        self.function = function.function(filepath, 1)

        self.assert_(self.function)

    def testExistence(self):
        assert self.function is not None

    def testNumInstructions(self):
        self.assertEqual(self.function.num_instructions, 1)

    def testStartAddress(self):
        # Test reading
        address = self.function.ea_start

        self.assertEqual(address, 0x40000)

        # Test writing
        self.function.ea_start = 0x40001
        self.assertEqual(self.function.ea_start, 0x40001)
        self.function.ea_start = 0x40000

    def testEndAddressProperty(self):
        # Test reading
        address = self.function.ea_end

        self.assertEqual(address, 0x40001)

        # Test writing
        self.function.ea_end = 0x40002
        self.assertEqual(self.function.ea_end, 0x40002)
        self.function.ea_end = 0x40001

    def testNameProperty(self):
        # Test reading
        name = self.function.name

        self.assertEqual(name, "loc_test")

        # Test writing
        self.function.name = "overwrite"
        self.assertEqual(self.function.name, "overwrite")
        self.function.name = "loc_test"

    # TODO Make import test

    # TODO Test flags

    def testSavedRegSize(self):
        # Test reading
        size = self.function.saved_reg_size

        self.assertEqual(size, 4)

        # Test writing
        self.function.saved_reg_size = 5
        self.assertEqual(self.function.saved_reg_size, 5)
        self.function.saved_reg_size = 4

    def testFrameSize(self):
        # Test reading
        size = self.function.frame_size

        self.assertEqual(size, 12)

        # Test writing
        self.function.frame_size = 15
        self.assertEqual(self.function.frame_size, 15)
        self.function.frame_size = 12

    def testRetSize(self):
        # Test reading
        size = self.function.ret_size

        self.assertEqual(size, 7)

        # Test writing
        self.function.ret_size = 9
        self.assertEqual(self.function.ret_size, 9)
        self.function.ret_size = 7

    def testLocalVarSize(self):
        # Test reading
        size = self.function.local_var_size

        self.assertEqual(size, 5)

        # Test writing
        self.function.local_var_size = 12
        self.assertEqual(self.function.local_var_size, 12)
        self.function.local_var_size = 5

    def testArgSize(self):
        # Test reading
        size = self.function.arg_size

        self.assertEqual(size, 3)

        # Test writing
        self.function.arg_size = 99
        self.assertEqual(self.function.arg_size, 99)
        self.function.arg_size = 3

    def testLocalVars(self):
        self.assertEqual(self.function.num_local_vars, 3)

    def testArgs(self):
        self.assertEqual(self.function.num_args, 2)

    # TODO test actual args and local_vars

    # TODO test RPC
class TestBasicBlockClass(unittest.TestCase):

    def setUp(self):
        filepath = os.getcwd() + "\\testdb"
        filepath = filepath.replace("\\", "/")
        self.basic_block = basic_block.basic_block(filepath,1)

        self.assert_(self.basic_block)

    def testStartAddressProperty(self):
        # Test reading
        address = self.basic_block.ea_start

        self.assertEqual(address, 0x40000)

        # Test writing
        self.basic_block.ea_start = 0x40001
        self.assertEqual(self.basic_block.ea_start, 0x40001)
        self.basic_block.ea_start = 0x40000

    def testEndAddressProperty(self):
        # Test reading
        address = self.basic_block.ea_end

        self.assertEqual(address, 0x40001)

        # Test writing
        self.basic_block.ea_end = 0x40002
        self.assertEqual(self.basic_block.ea_end, 0x40002)
        self.basic_block.ea_end = 0x40001

    def testNumInstructionsProperty(self):
        # Test reading

        self.assertEqual(self.basic_block.num_instructions, 1)

    def testSortedInstructions(self):
        # This will generate exceptions if the instuction class
        # is broken, but either way will fail the tests

        instructions = self.basic_block.sorted_instructions()

        self.assertEqual(len(instructions), 1)
        i = instructions[0]

        self.assertEqual(i.mnem, "test")
        self.assertEqual(i.basic_block, self.basic_block.dbid)
        self.assertEqual(i.ea, self.basic_block.ea_start)

class TestInstructionClass(unittest.TestCase):

    def setUp(self):
        # eventually check for a db with a set md5 hash
        filepath = os.getcwd() + "\\testdb"
        filepath = filepath.replace("\\", "/")
        self.instruction = instruction.instruction(filepath,1)

        self.assert_(self.instruction)

    def testCommentProperty(self):
        # Test reading
        comment = self.instruction.comment

        self.assertEqual(comment, "comment")

        # Test writing
        self.instruction.comment = "overwrite"
        self.assertEqual(self.instruction.comment, "overwrite")
        self.instruction.comment = "comment"

    def testBytesProperty(self):
        # Test reading
        bytes = self.instruction.bytes

        self.assertEqual(bytes, [0xFF, 0xFF])

        # Test writing
        self.instruction.bytes = [0xAA, 0xAA]
        self.assertEqual(self.instruction.bytes, [0xAA, 0xAA])
        self.instruction.bytes = [0xFF, 0xFF]

    def testAddressProperty(self):
        # Test reading
        address = self.instruction.ea

        self.assertEqual(address, 0x40000)

        # Test writing
        self.instruction.ea = 0x40001
        self.assertEqual(self.instruction.ea, 0x40001)
        self.instruction.ea = 0x40000

    def testMnemonicProperty(self):
        # Test reading
        mnem = self.instruction.mnem

        self.assertEqual(mnem, "test")

        # Test writing
        self.instruction.mnem = "nop"
        self.assertEqual(self.instruction.mnem, "nop")
        self.instruction.mnem = "test"

    def testOperand1Property(self):
        # Test reading
        op1 = self.instruction.op1

        self.assertEqual(op1, None)

        # Test writing
        self.instruction.op1 = "test"
        self.assertEqual(self.instruction.op1, "test")
        self.instruction.op1 = None

    def testOperand2Property(self):
        # Test reading
        op2 = self.instruction.op2

        self.assertEqual(op2, None)

        # Test writing
        self.instruction.op2 = "test"
        self.assertEqual(self.instruction.op2, "test")
        self.instruction.op2 = None

    def testOperand3Property(self):
        # Test reading
        op3 = self.instruction.op3

        self.assertEqual(op3, None)

        # Test writing
        self.instruction.op3 = "test"
        self.assertEqual(self.instruction.op3, "test")
        self.instruction.op3 = None

    def testDisasmProperty(self):
        self.instruction.op1 = "one"
        self.instruction.op2 = "two"
        self.instruction.op3 = "three"

        self.assertEqual(self.instruction.disasm, "test one, two, three")

        self.instruction.op1 = None
        self.instruction.op2 = None
        self.instruction.op3 = None

        self.assertEqual(self.instruction.disasm, "test")

if __name__ == '__main__':
    unittest.main()
