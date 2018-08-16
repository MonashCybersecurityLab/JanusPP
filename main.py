from sse_client import SSE_Client
from sse_server import SSE_Server
import os, pickle
from timeit import default_timer as timer
import sys
import ast
import argparse


d_level_arr = [10, 30, 50,100]
num_del_arr = [[2, 6, 10], [10, 20, 30], [10, 30, 50],[10,50,100]]
file_data_arr =  [i for i in range(1000, 11000, 1000)]

original_del = ['73', '583', '25', '863', '113', '137', '238', '54', '221', '607', '959', '236', '680', '300', '641', '976', '47', '435', '404', '186', '320', '801', '301', '414', '492', '645', '926', '370', '649', '713', '675', '600', '702', '135', '723', '536', '652', '240', '150', '595', '121', '574', '171', '81', '120', '62', '335', '955', '369', '495', '57', '970', '718', '573', '203', '996', '576', '487', '589', '478', '101', '754', '925', '530', '255', '165', '470', '710', '934', '921', '814', '885', '613', '569', '138', '817', '486', '937', '838', '93', '30', '556', '949', '664', '742', '4', '191', '575', '371', '187', '975', '677', '689', '197', '731', '878', '805', '548', '565', '897', '115', '832', '348', '939', '787', '581', '258', '393', '982', '668', '110', '225', '822', '15', '274', '729', '951', '27', '326', '907', '157', '415', '850', '502', '571', '531', '244', '296', '841', '317', '517', '144', '147', '950', '948', '881', '489', '24', '984', '410', '964', '590', '870', '95', '846', '229', '49', '630', '500', '430', '852', '336', '943', '685', '220', '188', '199', '482', '398', '128', '405', '550', '732', '671', '509', '481', '890', '14', '271', '78', '849', '736', '599', '323', '130', '374', '483', '883', '840', '477', '496', '862', '281', '422', '145', '479', '215', '633', '646', '297', '315', '957', '38', '947', '328', '227', '578', '622', '577', '380']
counter = 20
iv = os.urandom(16) 

for d_level in d_level_arr:
    for file_data in file_data_arr:
        filename = "inverted_index_" + str(file_data) + ".txt"
        universal_dict = {}
        with open(filename, "r") as f:        
                for line in f:
                    values = line.split(" ")
                    universal_dict[values[0]] = {str(x) for x in values[1:len(values)]}
        
        cur_del_no = num_del_arr[d_level_arr.index(d_level)] 

        for num_del in cur_del_no:
            del_array = original_del[:num_del]
            
            # initialise SSE_Client        
            client = SSE_Client(iv)
            print("")
            print(">>load: d= " + str(d_level) + " matched ids= " + str(file_data) + " num_del= " + str(num_del)) 
            client.initDict(universal_dict)
             
            print(">>>>>> encryption")
            start = timer()
            client.enc(d_level) 
            end = timer()
            print(">>>>>> time taken " + str((end - start)*1000) + " ms")
            
            print(">>>>>> deletion")
            start = timer()            
            for i in del_array:
                client.delfileId('Subject', i)
            end = timer()
            print(">>>>>> time taken " + str((end - start)*1000) + " ms")
             
            # client dumps to files
            client.dumpSKI_IV("ski_iv")
            client.dump_encrypted_index("encrypted_index")
            client.dump_deletion_paths("deletion_paths")
            client.dump_keyword_stage("keyword_stage")
            client.dump_deletion_enckey_tags("delkey_tags")
    
            # read data before giving to the server 
            encrypted_index = {}
            deletion_paths = {}
            keyword_stage = {}
            deletion_enckey_tags = {} 
              
            with open("ski_iv", "rb") as handle:
                (ski, iv) = pickle.load(handle)
                  
            with open("encrypted_index", "rb") as handle:
                encrypted_index = pickle.load(handle)       
              
            with open("deletion_paths", "rb") as handle:
                deletion_paths = pickle.load(handle)
              
            with open("keyword_stage", "rb") as handle:
                keyword_stage = pickle.load(handle) 
                     
            with open("delkey_tags", "rb") as handle:
                deletion_enckey_tags = pickle.load(handle) 
                  
            # initialize server and start searching
            server = SSE_Server(d_level, ski, iv, encrypted_index, deletion_paths, keyword_stage, deletion_enckey_tags)
              
            print(">>>>>> search for the keyword 'Subject' with " + str(counter) +" tests")
            keyword = 'Subject'
            token = client.token_generation(keyword)
            
            count = 0
            total_consump = 0.0
            while count < counter:
                start = timer()
                server.search(token)
                end = timer()
                total_consump += (end - start)  # total second
                count += 1

            avg = (total_consump / counter) * 1000  # in millisecond
            print(">>>>>> " + "average search time=" + str(avg) + " after testing " + str(counter) + " times")