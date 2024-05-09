import unittest
import main

class TestMain(unittest.TestCase):
    def test_port_spliter(self):
        self.assertEqual(main.port_spliter("1-2"), [1, 2])
        self.assertEqual(main.port_spliter("1-2,3"), [1, 2, 3])
        self.assertEqual(main.port_spliter("1-2,2"), [1, 2])
        self.assertEqual(main.port_spliter("-9-2,2"), [2])
        self.assertEqual(main.port_spliter("-9-2,65536"), [])
        self.assertEqual(main.port_spliter("65536"), [])
        self.assertEqual(main.port_spliter("0"), [0])
        self.assertEqual(main.port_spliter("1-2,4-5,6"), [1, 2, 4, 5, 6])
        self.assertEqual(main.port_spliter("1,4,6"), [1, 4, 6])
        self.assertEqual(main.port_spliter("4-1"), [1, 2, 3, 4])
        self.assertEqual(main.port_spliter("1"), [1])


if __name__ == '__main__':
    unittest.main()