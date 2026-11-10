import json
import unittest
from gitops import parse_vendor_output


class NativeManifestBoundary(unittest.TestCase):
    def test_native_multiple_documents_and_lists_are_supported(self):
        objects=[{'kind':'ConfigMap'},{'kind':'ServiceAccount'}]
        self.assertEqual(parse_vendor_output('\n'.join(json.dumps(v) for v in objects)),objects)
        self.assertEqual(parse_vendor_output(json.dumps({'kind':'List','items':objects})),objects)

    def test_invalid_trailing_document_is_rejected(self):
        with self.assertRaises(json.JSONDecodeError):parse_vendor_output('{"kind":"ConfigMap"}\nnot-json')


if __name__=='__main__':unittest.main()
