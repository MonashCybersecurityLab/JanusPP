import os, sys
import binascii
from Crypto.Cipher import AES
import pickle
import hashlib, hmac
from copy import deepcopy

_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}

class SSE_Client:
    
    def __init__(self, iv, key_length=32):

        self.SK0 = os.urandom(key_length)
        self.SKI = os.urandom(key_length) #for hmac generating secondary sk for keywords
        self.fixed_iv = iv
        
        self.encrypted_index = {}
        self.lookUp = {}
        
        self.keyword_keyseries = {}
        self.keyword_stage = {} #store the latest stage of each keyword
        self.deletion_paths = {} #store the deletion paths table
        self.deletion_enckey_tags = {} #store the deletion paths table
        
    def importKeys(self, keys):
        self.SK0 = keys[0]
        self.SKI = keys[1]
        self.fixed_iv = keys[2]
    
    def initDict(self, initial_lookUp):
        self.lookUp = initial_lookUp
         
    def crypto_primitives_hmac(self, key,msg):
        hash_msg = hmac.new(key, msg, hashlib.sha256).digest()
        return hash_msg
            
    def enc(self,d):

        self.encrypted_index.clear()
        iv = self.fixed_iv
        d = d +1 # to increase the root node
        for keyword in self.lookUp:

            #hash keyword first
            enc_keyword = self.crypto_primitives_hmac(self.SK0, bytes(keyword,'utf-8')) #this is used to encrypt the keyword
            encrypted_identifiers = set([])
            
            #generate sk series
            key_series = [0 for i in range(d)]
            sk = self.encrypt(self.keytrim(self.SK0),keyword, iv)
            key_series[0] = sk
            for i in range(1,d):
                next_sk = self.crypto_primitives_hmac(self.SKI,key_series[i-1])
                key_series[i] = next_sk          
                
            #store the key_series for the keyword
            self.keyword_keyseries[keyword] = key_series
            
            identifers = self.lookUp[keyword]           
            for identifier in identifers:
                
                t_id = self.string2HashedBinary(identifier) #binary of 8 digits                 
                k_id = 0
                #generate through over different d binary trees
                for key_item in key_series:                          
                        result =self.encrypt(self.keytrim(key_item),t_id[0], iv)
                        result =self.encrypt(self.keytrim(result),t_id[1],iv)
                        result =self.encrypt(self.keytrim(result),t_id[2],iv)
                        result =self.encrypt(self.keytrim(result),t_id[3],iv)
                        result =self.encrypt(self.keytrim(result),t_id[4],iv)
                        result =self.encrypt(self.keytrim(result),t_id[5],iv)
                        result =self.encrypt(self.keytrim(result),t_id[6],iv)
                        result =self.encrypt(self.keytrim(result),t_id[7],iv)
                        result =self.encrypt(self.keytrim(result),t_id[8],iv)
                        result =self.encrypt(self.keytrim(result),t_id[9],iv)
                        result =self.encrypt(self.keytrim(result),t_id[10],iv)
                        result =self.encrypt(self.keytrim(result),t_id[11],iv)
                        result =self.encrypt(self.keytrim(result),t_id[12],iv)
                        result =self.encrypt(self.keytrim(result),t_id[13],iv)
                        result =self.encrypt(self.keytrim(result),t_id[14],iv)
                        result =self.encrypt(self.keytrim(result),t_id[15],iv)
                        
                        int_result = int.from_bytes(result, sys.byteorder)
                        k_id = k_id ^ int_result

                #once we have k_id then we do hash as Cash paper to get encrypted keyword               
                encrypted_id = k_id^int(identifier)                
                encrypted_identifiers.add((encrypted_id,t_id))
              
            #then we add it into a tuple, finally we write to the file this dictionary
            self.encrypted_index[enc_keyword] =  encrypted_identifiers

    def delfileId(self, keyword, fileid):
        
        enc_keyword = self.crypto_primitives_hmac(self.SK0, bytes(keyword,'utf-8')) #this is used to encrypt the keyword
        path_tuples = []
        keyseries = self.keyword_keyseries[keyword]
        iv = self.fixed_iv
         
        t_id = self.string2HashedBinary(fileid)
             
        key_initiator = ''       
        if enc_keyword not in self.keyword_stage: #if the keyword has not been used in deletion
            key_initiator = keyseries[0]
        else:
            key_initiator = self.keyword_stage[enc_keyword][0]  
               
        traveled = ''
        for b_index in range(len(t_id)):
            if len(traveled)==0:
                if t_id[b_index] == '0':
                    result =self.encrypt(self.keytrim(key_initiator),'1', iv)
                    i_tuple= (result,'1')
                    path_tuples.append(i_tuple)
                else:
                    result =self.encrypt(self.keytrim(key_initiator),'0', iv)                       
                    i_tuple= (result,'0')
                    path_tuples.append(i_tuple)
                      
            else: # in case traveled path is not a starter
                t_path =''            
                if t_id[b_index] == '0':
                    t_path = traveled +'1'
                else: 
                    t_path = traveled +'0'
                    
                #encrypt in sequence again
                result = key_initiator
                for tranvers_digit in t_path:
                    result =self.encrypt(self.keytrim(result),tranvers_digit,iv)
                        
                i_tuple = (result,t_path)
                path_tuples.append(i_tuple)
                      
            traveled+= t_id[b_index]
            
        #add path_tuples and keyword into the deletion dictionary
        if enc_keyword not in self.deletion_paths:
            self.deletion_paths[enc_keyword] = [path_tuples]   
        else:
            self.deletion_paths[enc_keyword].append(path_tuples)   
    
        #update self.keyword_stage
        if enc_keyword not in self.keyword_stage:
            self.keyword_stage[enc_keyword] = (keyseries[1],1)
        else:
            next_deletion = self.keyword_stage[enc_keyword][1] + 1 
            next_key = keyseries[next_deletion]
            self.keyword_stage[enc_keyword] = (next_key,next_deletion)
        
        #update the self.deletion_tags 
        if enc_keyword not in self.deletion_enckey_tags:
            self.deletion_enckey_tags[enc_keyword] = set([t_id])
        else:
            self.deletion_enckey_tags[enc_keyword].add(t_id)
            
    def get_encrypted_index(self):
        return deepcopy(self.encrypted_index)
  
    def dumpKeys(self,filename):
        data =  (self.SK0, self.SKI,self.fixed_iv)
        with open(filename, "wb") as file:
            file.write(pickle.dumps(data))
        file.close()
            
    def dumpSKI_IV(self,filename):
        with open(filename, "wb") as file:
            file.write(pickle.dumps((self.SKI, self.fixed_iv)))
        file.close()
                
    def dump_encrypted_index(self,filename):
        with open(filename, "wb") as file:
            file.write(pickle.dumps(self.encrypted_index))
        file.close()
        
    def dump_keyword_stage(self,filename):
        with open(filename, "wb") as file:
            file.write(pickle.dumps(self.keyword_stage))
        file.close()
                    
    def dump_deletion_paths(self,filename):    
        with open(filename, "wb") as file:
            file.write(pickle.dumps(self.deletion_paths))           
        file.close()
    
    def dump_deletion_enckey_tags(self,filename):
        with open(filename, "wb") as file:
            file.write(pickle.dumps(self.deletion_enckey_tags))           
        file.close()
    
        
    def token_generation(self,keyword):
        enc_keyword = self.crypto_primitives_hmac(self.SK0, bytes(keyword,'utf-8'))
        return enc_keyword
                            
    def int_of_string(self,s):
        return int(binascii.hexlify(s), 16)  
    
    def keytrim(self, key):
        if len(key) == 32:
            return key
        if len(key) >= 32:
            return key[:32]
        else:
            return self._pad(key)

    def encrypt(self, key, raw, iv):
        raw = self._pad(raw)
        cipher = AES.new(key,AES.MODE_CBC,iv)
        return cipher.encrypt(raw)

    def decrypt(self,key, ctext,iv):
        cipher = AES.new(key,AES.MODE_CBC,iv)
        return self._unpad(cipher.decrypt(ctext))

    def _pad(self, s, bs=32):
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

    def utf8len(self,s):
        return len(s.encode('utf-8'))
    
    
    def string2HashedBinary(self, msg):
        
        msg_sign= bytes(msg,'utf-8')
        hashcode=hashlib.sha256(msg_sign).hexdigest()
        binary = lambda x: "".join(reversed( [i+j for i,j in zip( *[ ["{0:04b}".format(int(c,16)) for c in reversed("0"+x)][n::2] for n in [1,0] ] ) ] ))
        xor = lambda x,y: ''.join([_xormap[a, b] for a, b in zip(x, y)])
        
        bin_str = binary(hashcode)
        
        result1 = ''
        for i in range(0, len(bin_str),16):
            starter = i
            c1 = bin_str[starter:starter+8] 
            c2 = bin_str[starter+8:starter+16] 
            result1+= xor(c1, c2)
        
        result2= ''
        for i in range(0,len(result1),16):
            starter = i
            c1 = result1[starter:starter+8] 
            c2 = result1[starter+8:starter+16] 
            result2+= xor(c1, c2)           
     
        result3= ''    
        for i in range(0,len(result2),16):
            starter = i  
            c1 = result2[starter:starter+8] 
            c2 = result2[starter+8:starter+16]   
            result3+= xor(c1, c2)                            
    
        
        result4= ''    
        for i in range(0,len(result3),16):
            starter = i  
            c1 = result3[starter:starter+8] 
            c2 = result3[starter+8:starter+16]   
            result4+= xor(c1, c2)
    
        return result4