import unittest
from webhook import sign,verify,ReplayGuard
class Test(unittest.TestCase):
 def setUp(self): self.key=b'x'*32; self.body=b'{"ok":true}'; self.sig=sign(self.key,self.body,100,'event-1')
 def test_valid(self): self.assertTrue(verify(self.key,self.body,100,'event-1',self.sig,now=101))
 def test_tamper(self): self.assertFalse(verify(self.key,b'{}',100,'event-1',self.sig,now=101))
 def test_id_binding(self): self.assertFalse(verify(self.key,self.body,100,'event-2',self.sig,now=101))
 def test_stale(self): self.assertFalse(verify(self.key,self.body,100,'event-1',self.sig,now=401))
 def test_replay(self):
  g=ReplayGuard(); self.assertTrue(g.accept('event-1',100,now=100)); self.assertFalse(g.accept('event-1',100,now=101))
 def test_capacity(self):
  g=ReplayGuard(1); self.assertTrue(g.accept('a',100,now=100)); self.assertFalse(g.accept('b',100,now=100)); self.assertTrue(g.accept('b',401,now=401))
 def test_short_key(self):
  with self.assertRaises(ValueError): sign(b'x',b'',100,'a')
