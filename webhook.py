import hashlib,hmac,time,threading,re

def sign(secret:bytes,body:bytes,timestamp:int,event_id:str)->str:
    if not isinstance(secret,bytes) or len(secret)<32: raise ValueError('use a secret of at least 32 random bytes')
    if not isinstance(body,bytes) or type(timestamp) is not int or timestamp<0 or not isinstance(event_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',event_id): raise ValueError('invalid signing inputs')
    message=str(timestamp).encode()+b'.'+event_id.encode()+b'.'+body
    return 'v1='+hmac.new(secret,message,hashlib.sha256).hexdigest()
def verify(secret,body,timestamp,event_id,signature,*,now=None,tolerance=300):
    if type(timestamp) is not int or type(tolerance) is not int or not 0<tolerance<=3600: return False
    now=int(time.time()) if now is None else now
    if type(now) is not int or abs(now-timestamp)>tolerance or not isinstance(signature,str) or not re.fullmatch(r'v1=[0-9a-f]{64}',signature): return False
    try: expected=sign(secret,body,timestamp,event_id)
    except (ValueError,TypeError): return False
    return hmac.compare_digest(expected,signature)
class ReplayGuard:
    def __init__(self,capacity=10000):
        if type(capacity) is not int or capacity<1: raise ValueError('positive capacity required')
        self.capacity=capacity; self._seen={}; self._lock=threading.Lock()
    def accept(self,event_id,timestamp,*,now=None,tolerance=300):
        # Call only AFTER successful verify with the same parameters.
        now=int(time.time()) if now is None else now
        if not isinstance(event_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',event_id) or type(timestamp) is not int or type(now) is not int or type(tolerance) is not int or not 0<tolerance<=3600 or abs(now-timestamp)>tolerance: return False
        with self._lock:
            self._seen={k:v for k,v in self._seen.items() if v>=now}
            if event_id in self._seen or len(self._seen)>=self.capacity: return False
            self._seen[event_id]=timestamp+tolerance
            return True
