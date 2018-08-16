import sys
import hashlib, hmac
from Crypto.Cipher import AES

class SSE_Server:
    def __init__(self, d_level, ski, iv, encrypted_index, deletion_paths, keyword_stage, deletion_enckey_tags):
        
        self.d_level = d_level + 1 # to increase the root node 
        self.SKI = ski
        self.iv = iv    
        self.encrypted_index = encrypted_index
        self.deletion_paths = deletion_paths
        self.keyword_stage = keyword_stage
        self.deletion_enckey_tags = deletion_enckey_tags 
        
    def search(self, token):
        entries = self.encrypted_index[token]
        deletion_paths = self.deletion_paths[token]
        del_tags = self.deletion_enckey_tags[token]
        
        key_stage = self.keyword_stage[token][0]
        num_deletion = self.keyword_stage[token][1] 
        
        iv = self.iv

        for entry in entries:
            cur_tag = entry[1]
            if cur_tag not in del_tags:
                k_id = 0
                #it searches for historical deleted path to identify F(sk)
                for del_path in deletion_paths:
                    for del_item in del_path:
                        #check if the path is found
                        if  del_item[1] == cur_tag[0:len( del_item[1])]:
                            #select current key to aes in chain with next bits
                            if len( del_item[1]) !=16: #it means it is not exactly the same as the tag
                                result = del_item[0]
                                for i in range(len(del_item[1]),16):
                                    result =self.encrypt(self.keytrim(result),cur_tag[i],iv)
                                
                                k_id = k_id ^ int.from_bytes(result, sys.byteorder)
                            else:
                                k_id = k_id ^ int.from_bytes(del_item[0], sys.byteorder)
                            
                            break

                #depends on the d level- it find out its new F(sk) from the next keyword stage function
                #it do for d level - number of deletion
                d = num_deletion + 1
                cur_tag_key = key_stage
                while d <= self.d_level:
                    #get F function first
                    result =self.encrypt(self.keytrim(cur_tag_key),cur_tag[0], iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[1],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[2],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[3],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[4],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[5],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[6],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[7],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[8],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[9],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[10],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[11],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[12],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[13],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[14],iv)
                    result =self.encrypt(self.keytrim(result),cur_tag[15],iv)                    
                    int_result = int.from_bytes(result, sys.byteorder)
                    k_id = k_id ^ int_result
                    
                    #generate the next key then
                    
                    cur_tag_key = self.crypto_primitives_hmac(self.SKI,cur_tag_key)
                    d+=1
                    
                #xor to get file identifier again
                fileIdentifer = k_id ^ entry[0]
                #a.append(fileIdentifer)
        
        #print(a)       
    def crypto_primitives_hmac(self, key,msg):
        hash_msg = hmac.new(key, msg, hashlib.sha256).digest()
        return hash_msg
            
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
    
    def _pad(self, s, bs=32):
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)                      