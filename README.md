# JanusPP
The prototype demonstrates backward security in SSE [1].
The application is developed by using Python 3.6.
It requires Pycrypto 2.6.1 package.

Data set files with format. inverted_index_#####.txt contain the file identifiers of the Subject keyword.
sse_client.py demonstrates Client side
sse_server.py allows to search over the enrypted database.

main.py is the main application file. It can be executed by command, python3 main.py.

The main application demonstrates:
  + Setup with different data set
  + Encryption with time measurement
  + Deletion with time measurement
  + Search over the server.



Technical paper reference.
Shi-Feng Sun,Xingliang Yuan, Joseph Liu, Ron Steinfeld, Amin Sakzad,Viet Vo, Practical Backward-Secure Searchable Encryption from Symmetric Puncturable Encryption,
in CCS'18.
              


