import unittest
from app import app

class PostRouteTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_get_post_by_id_success(self):
        response = self.app.get('/posts/1')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['id'], 1)
        self.assertEqual(data['title'], 'First Post')

    def test_get_post_by_id_not_found(self):
        response = self.app.get('/posts/999')
        self.assertEqual(response.status_code, 404)
        data = response.get_json()
        self.assertIn('error', data)

if __name__ == '__main__':
    unittest.main()
